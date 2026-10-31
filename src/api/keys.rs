//! 密钥申请、邮箱验证与自助吊销。

use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::accounts;
use crate::api::helpers::{map_json_rejection, RequestContext};
use crate::crypto;
use crate::email::{
    check_email_daily_limit, increment_email_daily_count, redact_emails, templates,
    API_KEY_SUBJECT, VERIFICATION_SUBJECT,
};
use crate::error::ApiError;
use crate::html::escape_html;
use crate::models::ApiKeyRow;
use crate::state::AppState;
use crate::validate::{is_email_allowed, is_valid_email_format, normalize_email};

/// 验证令牌有效期。
const TOKEN_TTL_SECS: i64 = 30 * 60;

/// 申请接口对所有邮箱（已有密钥、新邮箱、被封禁）返回的同一段文字。
const REQUEST_ACCEPTED_MESSAGE: &str =
    "如果这个邮箱可以申请，验证邮件已发送，请在 30 分钟内打开邮件中的链接完成确认。";

/// 确认页与结果页统一的安全响应头。
fn html_response(body: String, status: StatusCode) -> Response {
    let mut response = Html(body).into_response();
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
        ),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn page_shell(title: &str, body: &str) -> String {
    // 共用样式：居中卡片与胶囊形主按钮；CSP 只允许内联样式，不引入脚本与外部资源
    format!(
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{}</title>\
         <style>\
         body{{margin:0;padding:2rem 1rem;background:#F4F1FF;color:#2D2A4A;\
         font-family:system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;\
         line-height:1.6;min-height:100vh;box-sizing:border-box;display:flex;\
         align-items:flex-start;justify-content:center}}\
         .card{{background:#fff;max-width:32em;width:100%;padding:2rem 1.75rem;\
         border-radius:16px;box-shadow:0 4px 24px rgba(108,92,231,.12);\
         border-top:4px solid #6C5CE7;box-sizing:border-box;margin:2rem 0}}\
         h1{{color:#6C5CE7;font-size:1.35rem;margin:0 0 .75rem}}\
         p{{color:#2D2A4A;margin:.5rem 0}}\
         button{{background:#F76707;color:#fff;border:none;border-radius:999px;\
         padding:.65rem 1.75rem;font-size:1rem;font-weight:600;cursor:pointer;\
         margin-top:.75rem}}\
         button:hover{{background:#e85c06}}\
         </style></head>\
         <body><main class=\"card\">{}</main></body></html>",
        escape_html(title),
        body
    )
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct VerifyPageParams {
    pub token: Option<String>,
}

#[utoipa::path(
    get,
    path = "/v1/keys/verify",
    operation_id = "verify_page",
    tag = "keys",
    params(("token" = String, Query, description = "一次性验证令牌")),
    responses(
        (status = 200, description = "确认页；令牌无效时为说明页。打开页面不改变任何状态"),
    )
)]
pub async fn verify_page(
    State(state): State<AppState>,
    ctx: RequestContext,
    Query(params): Query<VerifyPageParams>,
) -> Result<Response, ApiError> {
    state.limits.check_key_verify(&ctx.ip_hash)?;
    let token = params.token.unwrap_or_default();
    let record = lookup_verification(&state.pool, &token).await?;
    let page = match record {
        None => page_shell(
            "链接无效",
            "<h1>链接无效或已过期</h1><p>这个验证链接不存在、已被使用或已超过 30 分钟有效期。请重新申请密钥。</p>",
        ),
        Some(record) => {
            let action = if record.purpose == "reset" {
                "重置 API 密钥。确认后将生成新密钥，并<b>立即作废</b>你当前有效的密钥。"
            } else {
                "申请 API 密钥。确认后新密钥将发送到这个邮箱。"
            };
            page_shell(
                "确认操作",
                &format!(
                    "<h1>确认{}密钥</h1><p>你正在为这个邮箱{action}</p>\
                     <form method=\"post\" action=\"/v1/keys/verify\">\
                     <input type=\"hidden\" name=\"token\" value=\"{}\">\
                     <button type=\"submit\">确认</button></form>\
                     <p style=\"color:#666\">不是你本人的操作？直接关闭本页即可。</p>",
                    if record.purpose == "reset" { "重置" } else { "申请" },
                    escape_html(&token),
                ),
            )
        }
    };
    Ok(html_response(page, StatusCode::OK))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct VerifyForm {
    pub token: String,
}

#[utoipa::path(
    post,
    path = "/v1/keys/verify",
    operation_id = "verify_confirm",
    tag = "keys",
    responses(
        (status = 200, description = "结果页：密钥已发送，或发送失败提示稍后重试"),
    )
)]
pub async fn verify_confirm(
    State(state): State<AppState>,
    ctx: RequestContext,
    Form(form): Form<VerifyForm>,
) -> Result<Response, ApiError> {
    state.limits.check_key_verify(&ctx.ip_hash)?;
    // 确认流程包含发信与多段事务：放进独立任务，请求超时或客户端断开都不会让它
    // 停在“邮件已发出、密钥未激活”的半途。
    tokio::spawn(confirm_verification(state, form.token))
        .await
        .map_err(|error| ApiError::internal_with(format!("确认任务异常：{error}")))?
}

async fn confirm_verification(state: AppState, token: String) -> Result<Response, ApiError> {
    let token_hash = crypto::sha256_hex(token.as_bytes());
    let new_key = crypto::generate_api_key();

    // 事务 A：原子占用验证记录（未用且未过期）并登记 pending_delivery 密钥，随后立即提交
    let mut tx = state.pool.begin().await.map_err(ApiError::from)?;
    let claimed: Option<(Uuid, String, Vec<u8>, String)> = sqlx::query_as(
        "UPDATE email_verifications SET used_at = now()
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
         RETURNING id, email_hmac, email_ciphertext, purpose",
    )
    .bind(&token_hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::from)?;

    let Some((verification_id, email_hmac, email_ciphertext, purpose)) = claimed else {
        return Ok(html_response(
            page_shell(
                "链接无效",
                "<h1>链接无效或已过期</h1><p>这个验证链接不存在、已被使用或已超过 30 分钟有效期。请重新申请密钥。</p>",
            ),
            StatusCode::OK,
        ));
    };

    // 封禁的邮箱不发放密钥（事务回滚，验证记录保持未用）
    let banned: Option<String> =
        sqlx::query_scalar("SELECT reason FROM banned_accounts WHERE email_hmac = $1")
            .bind(&email_hmac)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::from)?;
    if banned.is_some() {
        tx.rollback().await.map_err(ApiError::from)?;
        tracing::info!(purpose = %purpose, "封禁邮箱的确认被拒绝");
        return Ok(html_response(
            page_shell(
                "无法发放",
                "<h1>无法为这个邮箱发放密钥</h1><p>如有疑问请联系管理员。</p>",
            ),
            StatusCode::OK,
        ));
    }

    let key_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO api_keys (id, key_prefix, key_hash, email_hmac, scopes, status)
         VALUES ($1, $2, $3, $4, '{read,write}', 'pending_delivery')",
    )
    .bind(key_id)
    .bind(crypto::key_prefix(&new_key))
    .bind(state.config.key_hash(&new_key))
    .bind(&email_hmac)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::from)?;
    tx.commit().await.map_err(ApiError::from)?;

    // 事务 A 之外的收尾：解密邮箱、检查全站每日上限、发信
    let rollback_pending = |key_id: Uuid, verification_id: Uuid| {
        let pool = state.pool.clone();
        async move {
            // 事务 C：删除 pending 密钥、恢复验证记录为未用，链接可以再试
            let mut tx = pool.begin().await?;
            sqlx::query("DELETE FROM api_keys WHERE id = $1 AND status = 'pending_delivery'")
                .bind(key_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("UPDATE email_verifications SET used_at = NULL WHERE id = $1")
                .bind(verification_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await.map_err(ApiError::from)
        }
    };

    let email = match state.cipher.decrypt(&email_hmac, &email_ciphertext) {
        Ok(email) => email,
        Err(error) => {
            tracing::error!(error = %error, "验证记录邮箱解密失败");
            if let Err(error) = rollback_pending(key_id, verification_id).await {
                tracing::error!(error = ?error, "回滚 pending 密钥失败");
            }
            return Ok(html_response(
                page_shell(
                    "出错了",
                    "<h1>暂时无法完成操作</h1><p>请稍后重新申请密钥。</p>",
                ),
                StatusCode::OK,
            ));
        }
    };

    let daily = check_email_daily_limit(&state.pool, state.config.email_daily_limit).await;
    if let Err(error) = daily {
        tracing::warn!("密钥邮件因全站每日上限未发送");
        if let Err(error) = rollback_pending(key_id, verification_id).await {
            tracing::error!(error = ?error, "回滚 pending 密钥失败");
        }
        let retry = error.retry_after.unwrap_or(3600).div_ceil(3600).max(1);
        return Ok(html_response(
            page_shell(
                "发送受限",
                &format!(
                    "<h1>今日发信已达上限</h1><p>大约 {retry} 小时后请重新打开邮件里的链接再点一次“确认”。</p>"
                ),
            ),
            StatusCode::OK,
        ));
    }

    // 邮件里的吊销链接：无状态 HMAC 令牌，打开确认页才真正吊销
    let revoke_link = format!(
        "{}/v1/keys/revoke?token={}",
        state.config.public_base_url,
        state.config.revoke_token(key_id)
    );
    let key_mail = templates::api_key_email(&new_key, &revoke_link);
    if let Err(error) = state
        .mailer
        .send(&email, API_KEY_SUBJECT, &key_mail.text, &key_mail.html)
        .await
    {
        tracing::error!(error = %redact_emails(&error), purpose = %purpose, "密钥邮件发送失败");
        if let Err(error) = rollback_pending(key_id, verification_id).await {
            tracing::error!(error = ?error, "回滚 pending 密钥失败");
        }
        return Ok(html_response(
            page_shell(
                "发送失败",
                "<h1>邮件发送失败</h1><p>稍后请重新打开邮件里的链接再点一次“确认”。</p>",
            ),
            StatusCode::OK,
        ));
    }

    // 事务 B：激活新密钥。失败时（含 pending 密钥已被清理）同样走事务 C，
    // 让链接可以重试；邮件里那把没激活的密钥随 pending 记录一起被删除，不会生效。
    match activate_key(&state.pool, &email_hmac, key_id, verification_id).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!("pending 密钥在确认过程中消失");
            if let Err(error) = rollback_pending(key_id, verification_id).await {
                tracing::error!(error = ?error, "恢复验证记录失败");
            }
            return Ok(unfinished_page());
        }
        Err(error) => {
            tracing::error!(error = ?error, "激活密钥失败");
            if let Err(error) = rollback_pending(key_id, verification_id).await {
                tracing::error!(error = ?error, "恢复验证记录失败");
            }
            return Ok(unfinished_page());
        }
    }

    // 密钥已发出并生效，计数失败只记日志，不能再向用户返回 500
    if let Err(error) =
        increment_email_daily_count(&state.pool, state.config.email_daily_limit).await
    {
        tracing::error!(error = ?error, "发信计数更新失败");
    }
    tracing::info!(purpose = %purpose, "密钥发放完成");

    Ok(html_response(
        page_shell(
            "操作完成",
            "<h1>密钥已发送到邮箱</h1><p>请到邮箱查收密钥邮件。没有收到时，检查垃圾邮件文件夹。</p>",
        ),
        StatusCode::OK,
    ))
}

/// 事务 B：按邮箱哈希加咨询锁串行化，吊销该账号其他 active 密钥、激活新密钥、清空邮箱密文。
/// 返回 `false` 表示 pending 密钥已不存在（事务回滚，没有任何改动）。
pub async fn activate_key(
    pool: &PgPool,
    email_hmac: &str,
    key_id: Uuid,
    verification_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(email_hmac)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE api_keys SET status = 'revoked', revoked_at = now() WHERE email_hmac = $1 AND status = 'active'",
    )
    .bind(email_hmac)
    .execute(&mut *tx)
    .await?;
    let activated = sqlx::query(
        "UPDATE api_keys SET status = 'active' WHERE id = $1 AND status = 'pending_delivery'",
    )
    .bind(key_id)
    .execute(&mut *tx)
    .await?;
    if activated.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    sqlx::query("UPDATE email_verifications SET email_ciphertext = ''::bytea WHERE id = $1")
        .bind(verification_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

fn unfinished_page() -> Response {
    html_response(
        page_shell(
            "操作未完成",
            "<h1>操作未完成</h1><p>请重新打开邮件里的验证链接，再点一次“确认”。</p>",
        ),
        StatusCode::OK,
    )
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct RevokePageParams {
    pub token: Option<String>,
}

/// 通用无效页：不区分令牌坏、密钥不存在还是已吊销。
fn revoke_invalid_page() -> Response {
    html_response(
        page_shell(
            "链接无效",
            "<h1>链接无效</h1><p>这个链接无效，或这把密钥已经被吊销。</p>",
        ),
        StatusCode::OK,
    )
}

/// 查令牌对应的密钥前缀；仅当令牌有效且密钥当前是 active 时返回。
async fn active_key_prefix(state: &AppState, token: &str) -> Result<Option<String>, ApiError> {
    let Some(key_id) = state.config.verify_revoke_token(token) else {
        return Ok(None);
    };
    let prefix: Option<String> =
        sqlx::query_scalar("SELECT key_prefix FROM api_keys WHERE id = $1 AND status = 'active'")
            .bind(key_id)
            .fetch_optional(&state.pool)
            .await?;
    Ok(prefix)
}

#[utoipa::path(
    get,
    path = "/v1/keys/revoke",
    operation_id = "revoke_page",
    tag = "keys",
    params(("token" = String, Query, description = "邮件里的吊销令牌")),
    responses(
        (status = 200, description = "确认页（仅 active 密钥）或通用无效页。GET 不改变任何状态"),
    )
)]
/// 吊销确认页。邮箱安全扫描会自动访问链接，因此 GET 绝不改变状态。
pub async fn revoke_page(
    State(state): State<AppState>,
    ctx: RequestContext,
    Query(params): Query<RevokePageParams>,
) -> Result<Response, ApiError> {
    state.limits.check_key_verify(&ctx.ip_hash)?;
    let token = params.token.unwrap_or_default();
    let prefix = active_key_prefix(&state, &token).await?;
    let Some(key_prefix) = prefix else {
        return Ok(revoke_invalid_page());
    };
    let page = page_shell(
        "确认吊销",
        &format!(
            "<h1>确认吊销密钥</h1>\
             <p>即将吊销密钥 <code>{}</code>。</p>\
             <p>吊销后使用这把密钥的插件会立刻失效。</p>\
             <p>之后可以用同一个邮箱重新申请新密钥。</p>\
             <form method=\"post\" action=\"/v1/keys/revoke\">\
             <input type=\"hidden\" name=\"token\" value=\"{}\">\
             <button type=\"submit\">确认吊销</button></form>",
            escape_html(&key_prefix),
            escape_html(&token),
        ),
    );
    Ok(html_response(page, StatusCode::OK))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RevokeForm {
    pub token: String,
}

#[utoipa::path(
    post,
    path = "/v1/keys/revoke",
    operation_id = "revoke_confirm",
    tag = "keys",
    request_body(content = RevokeForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "\"密钥已吊销\"页；令牌无效或密钥非 active 时为通用无效页（幂等）"),
    )
)]
/// 确认吊销：条件更新保证幂等，重复提交显示同一无效页。
pub async fn revoke_confirm(
    State(state): State<AppState>,
    ctx: RequestContext,
    Form(form): Form<RevokeForm>,
) -> Result<Response, ApiError> {
    state.limits.check_key_verify(&ctx.ip_hash)?;
    let Some(key_id) = state.config.verify_revoke_token(&form.token) else {
        return Ok(revoke_invalid_page());
    };
    let result = sqlx::query(
        "UPDATE api_keys SET status = 'revoked', revoked_at = now() WHERE id = $1 AND status = 'active'",
    )
    .bind(key_id)
    .execute(&state.pool)
    .await
    .map_err(ApiError::from)?;
    if result.rows_affected() == 1 {
        // 日志只记事件本身，不含令牌与密钥内容
        tracing::info!("密钥已通过邮件链接吊销");
        Ok(html_response(
            page_shell(
                "已吊销",
                "<h1>密钥已吊销</h1><p>使用这把密钥的插件会立刻失效。需要新密钥时，用同一个邮箱重新申请即可。</p>",
            ),
            StatusCode::OK,
        ))
    } else {
        Ok(revoke_invalid_page())
    }
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct KeyRequestBody {
    pub email: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RequestKeyResponse {
    pub message: String,
}

#[utoipa::path(
    post,
    path = "/v1/keys/request",
    operation_id = "request_key",
    tag = "keys",
    request_body = KeyRequestBody,
    responses(
        (status = 202, description = "无论邮箱是否已有密钥都返回相同结果", body = RequestKeyResponse),
        (status = 400, description = "邮箱格式无效或不在白名单（email_not_allowed）"),
        (status = 429, description = "触发冷却时间、每日上限或 IP 频率限制"),
    )
)]
pub async fn request_key(
    State(state): State<AppState>,
    ctx: RequestContext,
    body: Result<Json<KeyRequestBody>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<RequestKeyResponse>), ApiError> {
    state.limits.check_key_request(&ctx.ip_hash)?;
    let body = body.map_err(|rejection| map_json_rejection(&rejection))?;
    let email = normalize_email(&body.email);
    if !is_valid_email_format(&email) {
        return Err(ApiError::bad_request("邮箱格式无效"));
    }
    if !is_email_allowed(&email, &state.config.email_domain_allowlist) {
        return Err(ApiError::new(
            crate::error::ErrorCode::EmailNotAllowed,
            "该邮箱后缀不在允许名单内",
        ));
    }
    // 身份与发信地址解耦：HMAC 用规范化身份，邮件发到用户填写的地址
    let email_hmac = state.config.account_hmac(&email);

    // 冷却时间：同一邮箱 10 分钟内只发一封。
    // 以下三项检查对所有邮箱一视同仁（被封禁的也一样），否则连续两次申请的响应差异
    // 会暴露封禁状态。
    let cooldown_secs = state.config.email_cooldown_secs as i64;
    let recent: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT max(created_at) FROM email_verifications WHERE email_hmac = $1 AND created_at > now() - make_interval(secs => $2)",
    )
    .bind(&email_hmac)
    .bind(cooldown_secs)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::from)?
    .flatten();
    if let Some(last) = recent {
        let elapsed = (chrono::Utc::now() - last).num_seconds().max(0);
        return Err(ApiError::rate_limited(
            (cooldown_secs - elapsed).max(1) as u64
        ));
    }

    // 每日上限：同一邮箱每天最多 N 封
    let per_day = state.config.email_per_day_limit as i64;
    let today_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM email_verifications WHERE email_hmac = $1 AND created_at >= date_trunc('day', now())",
    )
    .bind(&email_hmac)
    .fetch_one(&state.pool)
    .await
    .map_err(ApiError::from)?;
    if today_count >= per_day {
        return Err(ApiError::rate_limited(3600));
    }

    // 全站每日发信上限
    check_email_daily_limit(&state.pool, state.config.email_daily_limit).await?;

    let banned = accounts::is_banned(&state.pool, &email_hmac).await?;
    // 邮箱当前有 active 密钥 → 重置措辞，否则申请
    let has_active: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM api_keys WHERE email_hmac = $1 AND status = 'active' LIMIT 1",
    )
    .bind(&email_hmac)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::from)?;
    let purpose = if has_active.is_some() {
        "reset"
    } else {
        "issue"
    };

    // 被封禁的邮箱也登记一条验证记录（占用冷却与每日额度），但令牌从未发出，
    // 记录直接标记为已用、不保存邮箱密文，之后不会被确认。
    let token = crypto::generate_token();
    let token_hash = crypto::sha256_hex(token.as_bytes());
    let ciphertext = if banned {
        Vec::new()
    } else {
        state.cipher.encrypt(&email_hmac, &email)
    };
    sqlx::query(
        "INSERT INTO email_verifications (id, token_hash, email_hmac, email_ciphertext, purpose, expires_at, ip_hash, used_at)
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6), $7, CASE WHEN $8 THEN now() END)",
    )
    .bind(Uuid::new_v4())
    .bind(&token_hash)
    .bind(&email_hmac)
    .bind(ciphertext)
    .bind(purpose)
    .bind(TOKEN_TTL_SECS)
    .bind(&ctx.ip_hash)
    .bind(banned)
    .execute(&state.pool)
    .await
    .map_err(ApiError::from)?;

    if banned {
        tracing::info!("封禁邮箱申请密钥：静默返回 202，不发信");
    } else {
        let link = format!(
            "{}/v1/keys/verify?token={}",
            state.config.public_base_url, token
        );
        let verification_mail = templates::verification_email(purpose, &link);
        let send_result = state
            .mailer
            .send(
                &email,
                VERIFICATION_SUBJECT,
                &verification_mail.text,
                &verification_mail.html,
            )
            .await;
        match send_result {
            Ok(()) => {
                // 邮件已发出，计数失败只记日志
                if let Err(error) =
                    increment_email_daily_count(&state.pool, state.config.email_daily_limit).await
                {
                    tracing::error!(error = ?error, "发信计数更新失败");
                }
            }
            Err(error) => {
                // 不向外暴露发信失败细节；记录保留以维持冷却时间
                tracing::error!(error = %redact_emails(&error), "验证邮件发送失败");
            }
        }
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(RequestKeyResponse {
            message: REQUEST_ACCEPTED_MESSAGE.to_string(),
        }),
    ))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct KeyInfo {
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub status: String,
    #[schema(value_type = String)]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub rate_limits: serde_json::Value,
}

#[utoipa::path(
    get,
    path = "/v1/key",
    operation_id = "key_info",
    tag = "keys",
    responses(
        (status = 200, description = "当前密钥信息（插件的“测试连接”）", body = KeyInfo),
        (status = 401, description = "密钥无效"),
    )
)]
pub async fn key_info(
    State(state): State<AppState>,
    ctx: RequestContext,
) -> Result<Json<KeyInfo>, ApiError> {
    ctx.check_read_limit(&state)?;
    let key = ctx.require_key()?;
    let rate_limits = serde_json::json!({
        "read_per_minute": state.config.rate_limits.keyed_read_per_min,
        "write_per_minute": state.config.rate_limits.write_per_min,
    });
    Ok(Json(KeyInfo {
        key_prefix: key.key_prefix.clone(),
        scopes: key.scopes.clone(),
        status: key.status.clone(),
        created_at: key.created_at,
        rate_limits,
    }))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RevokeResponse {
    pub status: String,
}

#[utoipa::path(
    delete,
    path = "/v1/key",
    operation_id = "revoke_own_key",
    tag = "keys",
    responses(
        (status = 200, description = "已吊销当前密钥", body = RevokeResponse),
        (status = 401, description = "密钥无效"),
    )
)]
pub async fn revoke_own_key(
    State(state): State<AppState>,
    ctx: RequestContext,
) -> Result<Json<RevokeResponse>, ApiError> {
    let key = ctx.require_key()?;
    sqlx::query("UPDATE api_keys SET status = 'revoked', revoked_at = now() WHERE id = $1")
        .bind(key.id)
        .execute(&state.pool)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(RevokeResponse {
        status: "revoked".to_string(),
    }))
}

struct VerificationRecord {
    #[allow(dead_code)]
    id: Uuid,
    purpose: String,
}

/// 令牌有效性查询（不改变状态）。
async fn lookup_verification(
    pool: &PgPool,
    token: &str,
) -> Result<Option<VerificationRecord>, ApiError> {
    if token.is_empty() {
        return Ok(None);
    }
    let token_hash = crypto::sha256_hex(token.as_bytes());
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, purpose FROM email_verifications
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()",
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await
    .map_err(ApiError::from)?;
    Ok(row.map(|(id, purpose)| VerificationRecord { id, purpose }))
}

/// 供管理员创建密钥复用的插入逻辑。
pub async fn insert_active_key(
    pool: &PgPool,
    key: &str,
    key_hash: &str,
    email_hmac: &str,
    scopes: &[String],
) -> Result<ApiKeyRow, ApiError> {
    let scopes: Vec<String> = scopes.to_vec();
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO api_keys (id, key_prefix, key_hash, email_hmac, scopes, status)
         VALUES ($1, $2, $3, $4, $5, 'active')",
    )
    .bind(id)
    .bind(crypto::key_prefix(key))
    .bind(key_hash)
    .bind(email_hmac)
    .bind(&scopes)
    .execute(pool)
    .await
    .map_err(ApiError::from)?;
    let row = ApiKeyRow {
        id,
        key_prefix: crypto::key_prefix(key),
        key_hash: key_hash.to_string(),
        email_hmac: email_hmac.to_string(),
        scopes,
        status: "active".to_string(),
        created_at: chrono::Utc::now(),
        revoked_at: None,
        last_used_at: None,
    };
    Ok(row)
}
