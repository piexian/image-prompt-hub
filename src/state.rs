//! 应用状态与初始化流程（连接池、迁移、索引、快照、后台任务）。

use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::catalog::Catalog;
use crate::config::Config;
use crate::crypto::EmailCipher;
use crate::email::Mailer;
use crate::error::ApiError;
use crate::ratelimit::RateLimiters;
use crate::search::SearchIndex;

pub struct AppStateInner {
    pub config: Config,
    pub pool: PgPool,
    pub index: SearchIndex,
    pub catalog: Catalog,
    pub limits: RateLimiters,
    pub mailer: Arc<dyn Mailer>,
    pub cipher: EmailCipher,
    /// 跟踪后台发信任务：申请接口发信放后台，退出前等待收尾。
    pub mail_tasks: tokio_util::task::TaskTracker,
}

#[derive(Clone)]
pub struct AppState(pub Arc<AppStateInner>);

impl std::ops::Deref for AppState {
    type Target = AppStateInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub async fn connect_pool(database_url: &str) -> Result<PgPool, ApiError> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
        .map_err(|e| ApiError::internal_with(format!("数据库连接失败：{e}")))
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), ApiError> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| ApiError::internal_with(format!("数据库迁移失败：{e}")))?;
    Ok(())
}

/// 组装完整状态并启动后台任务；启动时生成一次快照。
pub async fn build_state(config: Config, mailer: Arc<dyn Mailer>) -> Result<AppState, ApiError> {
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|e| ApiError::internal_with(format!("创建数据目录失败：{e}")))?;
    let pool = connect_pool(&config.secrets.database_url).await?;
    run_migrations(&pool).await?;

    let index = SearchIndex::open(&config.data_dir.join("index"), &pool).await?;
    let catalog = Catalog::new(&config.data_dir);
    catalog.regenerate(&pool).await?;

    let limits = RateLimiters::new(config.rate_limits);
    let cipher = EmailCipher::new(&config.secrets.email_enc_key);

    crate::catalog::spawn_worker(catalog.clone(), pool.clone(), config.catalog_debounce_secs);
    spawn_index_sync_worker(
        index.clone(),
        catalog.clone(),
        pool.clone(),
        config.index_sync_interval_secs,
    );
    spawn_cleanup_worker(pool.clone());
    spawn_ratelimit_retention_worker(limits.clone());

    Ok(AppState(Arc::new(AppStateInner {
        config,
        pool,
        index,
        catalog,
        limits,
        mailer,
        cipher,
        mail_tasks: tokio_util::task::TaskTracker::new(),
    })))
}

/// 对账回看秒数：至少 5 分钟，且覆盖两个对账周期（多留 60 秒余量），
/// 防止对账间隔超过 5 分钟时隐藏操作落在窗口外被漏掉。
pub fn index_sync_lookback_secs(interval_secs: u64) -> u64 {
    interval_secs.saturating_mul(2).saturating_add(60).max(300)
}

/// 检索索引对账：定期把最近被隐藏的模板从索引与目录快照里去掉。
/// 不依赖通知，对任何绕过 HTTP 接口的隐藏（如命令行 ban）都有效；
/// 提交的 Delete 由索引后台任务按数据库当前状态执行，重复提交幂等。
/// 5 分钟回看窗口让较长的事务或错过的轮次也能被后续轮次补上。
fn spawn_index_sync_worker(
    index: crate::search::SearchIndex,
    catalog: Catalog,
    pool: PgPool,
    interval_secs: u64,
) {
    // 回看窗口随间隔自动放宽，间隔大时也能覆盖到两轮之间被隐藏的模板
    let lookback_secs = index_sync_lookback_secs(interval_secs);
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(interval_secs.max(1)));
        loop {
            interval.tick().await;
            let hidden: Result<Vec<String>, _> = sqlx::query_scalar(
                "SELECT id FROM templates
                 WHERE status = 'hidden' AND updated_at >= now() - make_interval(secs => $1)",
            )
            .bind(lookback_secs as f64)
            .fetch_all(&pool)
            .await;
            match hidden {
                Ok(ids) if ids.is_empty() => {}
                Ok(ids) => {
                    for id in &ids {
                        index.submit(crate::search::IndexOp::Delete(id.clone()));
                    }
                    catalog.mark_dirty();
                }
                Err(error) => {
                    // 查询失败只记日志，下一轮继续
                    tracing::error!(error = %error, "索引对账查询失败");
                }
            }
        }
    });
}

/// 每 5 分钟清理限流器里已恢复满额度的键并收缩存储，防止按 IP/密钥的状态无限增长。
fn spawn_ratelimit_retention_worker(limits: crate::ratelimit::RateLimiters) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            limits.retain_and_shrink();
            tracing::debug!(keys = limits.tracked_keys(), "限流器状态已清理");
        }
    });
}

/// 定期执行 [`run_cleanup`]。
fn spawn_cleanup_worker(pool: PgPool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            interval.tick().await;
            run_cleanup(&pool).await;
        }
    });
}

/// 清理一轮：过期验证记录的邮箱密文清空、过期很久的验证记录删除、
/// 卡在 pending_delivery 的密钥（发信中断或确认事务失败遗留）删除。
/// 各步独立，单步失败只记日志，不影响其余步骤。
pub async fn run_cleanup(pool: &PgPool) {
    if let Err(error) = sqlx::query(
        "UPDATE email_verifications SET email_ciphertext = ''::bytea
         WHERE email_ciphertext <> ''::bytea AND expires_at < now()",
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = %error, "清理过期邮箱密文失败");
    }
    if let Err(error) =
        sqlx::query("DELETE FROM email_verifications WHERE expires_at < now() - interval '7 days'")
            .execute(pool)
            .await
    {
        tracing::error!(error = %error, "删除过期验证记录失败");
    }
    if let Err(error) = sqlx::query(
        "DELETE FROM api_keys
         WHERE status = 'pending_delivery' AND created_at < now() - interval '1 hour'",
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = %error, "清理 pending 密钥失败");
    }
}

#[cfg(test)]
mod tests {
    use super::index_sync_lookback_secs;

    #[test]
    fn lookback_covers_interval_and_floor() {
        // 小间隔回落到 5 分钟下限
        assert_eq!(index_sync_lookback_secs(1), 300);
        assert_eq!(index_sync_lookback_secs(30), 300);
        assert_eq!(index_sync_lookback_secs(120), 300);
        // 间隔 10 分钟：2 倍加 60 = 1260
        assert_eq!(index_sync_lookback_secs(600), 1260);
        assert_eq!(index_sync_lookback_secs(300), 660);
        // 极大间隔不溢出
        assert_eq!(index_sync_lookback_secs(u64::MAX), u64::MAX);
        assert_eq!(index_sync_lookback_secs(u64::MAX / 2 + 1), u64::MAX);
    }
}
