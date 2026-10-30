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
    })))
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
