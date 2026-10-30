//! 账号封禁与解封：管理接口与命令行共用同一条数据库路径。

use sqlx::PgPool;

use crate::error::ApiError;

pub struct BanOutcome {
    pub revoked_keys: u64,
    /// 被隐藏的模板 ID；调用方负责同步检索索引与目录快照。
    pub hidden_template_ids: Vec<String>,
}

pub async fn is_banned(pool: &PgPool, email_hmac: &str) -> Result<bool, ApiError> {
    let banned: Option<String> =
        sqlx::query_scalar("SELECT reason FROM banned_accounts WHERE email_hmac = $1")
            .bind(email_hmac)
            .fetch_optional(pool)
            .await?;
    Ok(banned.is_some())
}

/// 封禁账号：登记封禁、吊销其全部密钥（含发信中的 pending 密钥），
/// `hide_templates` 为真时把全部 published 模板改为 hidden。三步在同一事务里完成，
/// 重复封禁是幂等的（更新理由）。
pub async fn ban(
    pool: &PgPool,
    email_hmac: &str,
    reason: &str,
    hide_templates: bool,
) -> Result<BanOutcome, ApiError> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO banned_accounts (email_hmac, reason) VALUES ($1, $2)
         ON CONFLICT (email_hmac) DO UPDATE SET reason = $2, created_at = now()",
    )
    .bind(email_hmac)
    .bind(reason)
    .execute(&mut *tx)
    .await?;
    let revoked = sqlx::query(
        "UPDATE api_keys SET status = 'revoked', revoked_at = now()
         WHERE email_hmac = $1 AND status <> 'revoked'",
    )
    .bind(email_hmac)
    .execute(&mut *tx)
    .await?;
    let hidden_template_ids: Vec<String> = if hide_templates {
        sqlx::query_scalar(
            "UPDATE templates SET status = 'hidden', updated_at = now()
             WHERE owner_email_hmac = $1 AND status = 'published'
             RETURNING id",
        )
        .bind(email_hmac)
        .fetch_all(&mut *tx)
        .await?
    } else {
        Vec::new()
    };
    tx.commit().await?;
    Ok(BanOutcome {
        revoked_keys: revoked.rows_affected(),
        hidden_template_ids,
    })
}

/// 解除封禁，不恢复模板。返回账号此前是否在封禁名单里。
pub async fn unban(pool: &PgPool, email_hmac: &str) -> Result<bool, ApiError> {
    let result = sqlx::query("DELETE FROM banned_accounts WHERE email_hmac = $1")
        .bind(email_hmac)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
