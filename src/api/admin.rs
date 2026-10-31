//! 管理接口：举报列表、模板下架与恢复、按邮箱查密钥、吊销密钥。

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::accounts;
use crate::api::helpers::{map_json_rejection, parse_limit, RequestContext};
use crate::error::ApiError;
use crate::models::TemplateRow;
use crate::search::IndexOp;
use crate::state::AppState;
use crate::validate::has_forbidden_control;

const UPD_TEMPLATE_STATUS: &str = "UPDATE templates SET status = $2, updated_at = now() WHERE id = $1 AND status = ANY($3) RETURNING id, name, ai_description, content, defaults, reference, tags, author, source_url, owner_key_id, owner_email_hmac, status, version, created_at, updated_at";

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ReportsParams {
    pub limit: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReportEntry {
    pub id: Uuid,
    pub template_id: String,
    pub reason: String,
    #[schema(value_type = String)]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReportsResponse {
    pub reports: Vec<ReportEntry>,
}

#[utoipa::path(
    get,
    path = "/v1/admin/reports",
    operation_id = "admin_reports",
    tag = "admin",
    params(ReportsParams),
    responses(
        (status = 200, description = "举报列表，最新在前", body = ReportsResponse),
        (status = 401, description = "密钥无效"),
        (status = 403, description = "没有 admin 权限"),
    )
)]
pub async fn list_reports(
    State(state): State<AppState>,
    ctx: RequestContext,
    Query(params): Query<ReportsParams>,
) -> Result<Json<ReportsResponse>, ApiError> {
    ctx.require_admin()?;
    ctx.check_read_limit(&state)?;
    let limit = parse_limit(&params.limit, 50, 200)?;
    let rows: Vec<(Uuid, String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, template_id, reason, created_at FROM reports ORDER BY created_at DESC LIMIT $1",
    )
    .bind(limit as i64)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(ReportsResponse {
        reports: rows
            .into_iter()
            .map(|(id, template_id, reason, created_at)| ReportEntry {
                id,
                template_id,
                reason,
                created_at,
            })
            .collect(),
    }))
}

async fn set_template_status(
    state: &AppState,
    id: &str,
    from: &[&str],
    to: &str,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row: Option<TemplateRow> = sqlx::query_as(UPD_TEMPLATE_STATUS)
        .bind(id)
        .bind(to)
        .bind(from)
        .fetch_optional(&state.pool)
        .await?;
    match row {
        None => Err(ApiError::not_found()),
        Some(row) => {
            if to == "published" {
                state.index.submit(IndexOp::Upsert(row.id.clone()));
            } else {
                state.index.submit(IndexOp::Delete(row.id.clone()));
            }
            state.catalog.mark_dirty();
            Ok(Json(
                serde_json::json!({"id": row.id, "status": row.status}),
            ))
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StatusChangeResponse {
    pub id: String,
    pub status: String,
}

#[utoipa::path(
    post,
    path = "/v1/admin/templates/{id}/hide",
    operation_id = "admin_hide",
    tag = "admin",
    params(("id" = String, Path, description = "模板 ID")),
    responses(
        (status = 200, description = "已下架，检索与目录快照不再出现", body = StatusChangeResponse),
        (status = 401, description = "密钥无效"),
        (status = 403, description = "没有 admin 权限"),
        (status = 404, description = "模板不存在或不在可下架状态"),
    )
)]
pub async fn hide_template(
    State(state): State<AppState>,
    ctx: RequestContext,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ctx.require_admin()?;
    ctx.check_read_limit(&state)?;
    set_template_status(&state, &id, &["published"], "hidden").await
}

#[utoipa::path(
    post,
    path = "/v1/admin/templates/{id}/restore",
    operation_id = "admin_restore",
    tag = "admin",
    params(("id" = String, Path, description = "模板 ID")),
    responses(
        (status = 200, description = "已恢复公开", body = StatusChangeResponse),
        (status = 401, description = "密钥无效"),
        (status = 403, description = "没有 admin 权限"),
        (status = 404, description = "模板不存在或不在可恢复状态"),
    )
)]
pub async fn restore_template(
    State(state): State<AppState>,
    ctx: RequestContext,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ctx.require_admin()?;
    ctx.check_read_limit(&state)?;
    set_template_status(&state, &id, &["hidden"], "published").await
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AdminKeysLookupBody {
    pub email: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AdminKeyEntry {
    pub id: Uuid,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub status: String,
    #[schema(value_type = String)]
    pub created_at: DateTime<Utc>,
    #[schema(value_type = Option<String>)]
    pub revoked_at: Option<DateTime<Utc>>,
    #[schema(value_type = Option<String>)]
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AdminKeysResponse {
    pub keys: Vec<AdminKeyEntry>,
}

#[utoipa::path(
    post,
    path = "/v1/admin/keys/lookup",
    operation_id = "admin_keys_lookup",
    tag = "admin",
    request_body = AdminKeysLookupBody,
    responses(
        (status = 200, description = "该邮箱的全部密钥（按邮箱哈希查询；用 POST 避免邮箱进中间层日志）", body = AdminKeysResponse),
        (status = 401, description = "密钥无效"),
        (status = 403, description = "没有 admin 权限"),
    )
)]
pub async fn lookup_keys_by_email(
    State(state): State<AppState>,
    ctx: RequestContext,
    body: Result<Json<AdminKeysLookupBody>, JsonRejection>,
) -> Result<Json<AdminKeysResponse>, ApiError> {
    ctx.require_admin()?;
    ctx.check_read_limit(&state)?;
    let Json(body) = body.map_err(|rejection| map_json_rejection(&rejection))?;
    let email_hmac = state.config.account_hmac(&body.email);
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        key_prefix: String,
        scopes: Vec<String>,
        status: String,
        created_at: DateTime<Utc>,
        revoked_at: Option<DateTime<Utc>>,
        last_used_at: Option<DateTime<Utc>>,
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, key_prefix, scopes, status, created_at, revoked_at, last_used_at
         FROM api_keys WHERE email_hmac = $1 ORDER BY created_at DESC",
    )
    .bind(&email_hmac)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(AdminKeysResponse {
        keys: rows
            .into_iter()
            .map(|row| AdminKeyEntry {
                id: row.id,
                key_prefix: row.key_prefix,
                scopes: row.scopes,
                status: row.status,
                created_at: row.created_at,
                revoked_at: row.revoked_at,
                last_used_at: row.last_used_at,
            })
            .collect(),
    }))
}

#[utoipa::path(
    delete,
    path = "/v1/admin/keys/{key_id}",
    operation_id = "admin_revoke_key",
    tag = "admin",
    params(("key_id" = Uuid, Path, description = "密钥 ID")),
    responses(
        (status = 200, description = "已吊销"),
        (status = 401, description = "密钥无效"),
        (status = 403, description = "没有 admin 权限"),
        (status = 404, description = "密钥不存在"),
    )
)]
pub async fn revoke_key(
    State(state): State<AppState>,
    ctx: RequestContext,
    Path(key_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    ctx.require_admin()?;
    ctx.check_read_limit(&state)?;
    let result = sqlx::query(
        "UPDATE api_keys SET status = 'revoked', revoked_at = now() WHERE id = $1 AND status <> 'revoked'",
    )
    .bind(key_id)
    .execute(&state.pool)
    .await?;
    if result.rows_affected() == 0 {
        // 幂等：已吊销的密钥再次吊销视为成功
        let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM api_keys WHERE id = $1")
            .bind(key_id)
            .fetch_optional(&state.pool)
            .await?;
        if exists.is_none() {
            return Err(ApiError::not_found());
        }
    }
    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct BanBody {
    /// 与 key_id 二选一
    pub email: Option<String>,
    pub key_id: Option<Uuid>,
    pub reason: String,
    #[serde(default)]
    pub hide_templates: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BanResponse {
    pub email_hmac: String,
    pub revoked_keys: u64,
    pub hidden_templates: u64,
}

/// 定位账号身份：邮箱或密钥 ID 二选一，两者都给或都不给都是 400，避免定位到意料之外的账号。
async fn resolve_email_hmac(
    state: &AppState,
    email: Option<&str>,
    key_id: Option<Uuid>,
) -> Result<String, ApiError> {
    let email = email.filter(|e| !e.trim().is_empty());
    match (email, key_id) {
        (Some(_), Some(_)) => Err(ApiError::bad_request("email 与 key_id 只能提供其一")),
        (Some(email), None) => Ok(state.config.account_hmac(email)),
        (None, Some(key_id)) => {
            let email_hmac: Option<String> =
                sqlx::query_scalar("SELECT email_hmac FROM api_keys WHERE id = $1")
                    .bind(key_id)
                    .fetch_optional(&state.pool)
                    .await?;
            email_hmac.ok_or_else(ApiError::not_found)
        }
        (None, None) => Err(ApiError::bad_request("email 与 key_id 必须提供其一")),
    }
}

#[utoipa::path(
    post,
    path = "/v1/admin/accounts/ban",
    operation_id = "admin_ban_account",
    tag = "admin",
    request_body = BanBody,
    responses(
        (status = 200, description = "已封禁并吊销该账号全部密钥", body = BanResponse),
        (status = 400, description = "email 与 key_id 必须二选一"),
        (status = 401, description = "密钥无效"),
        (status = 403, description = "没有 admin 权限"),
        (status = 404, description = "key_id 不存在"),
    )
)]
pub async fn ban_account(
    State(state): State<AppState>,
    ctx: RequestContext,
    body: Result<Json<BanBody>, JsonRejection>,
) -> Result<Json<BanResponse>, ApiError> {
    ctx.require_admin()?;
    ctx.check_read_limit(&state)?;
    let Json(body) = body.map_err(|rejection| map_json_rejection(&rejection))?;
    let reason = body.reason.trim();
    if reason.is_empty() || reason.chars().count() > 500 || has_forbidden_control(reason) {
        return Err(ApiError::bad_request("reason 必须是 1 到 500 字的文本"));
    }
    let email_hmac = resolve_email_hmac(&state, body.email.as_deref(), body.key_id).await?;

    let outcome = accounts::ban(&state.pool, &email_hmac, reason, body.hide_templates).await?;
    for id in &outcome.hidden_template_ids {
        state.index.submit(IndexOp::Delete(id.clone()));
    }
    if !outcome.hidden_template_ids.is_empty() {
        state.catalog.mark_dirty();
    }
    tracing::info!(
        hidden_templates = outcome.hidden_template_ids.len(),
        revoked_keys = outcome.revoked_keys,
        "账号已封禁"
    );
    Ok(Json(BanResponse {
        email_hmac,
        revoked_keys: outcome.revoked_keys,
        hidden_templates: outcome.hidden_template_ids.len() as u64,
    }))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UnbanBody {
    /// 与 key_id 二选一
    pub email: Option<String>,
    pub key_id: Option<Uuid>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UnbanResponse {
    pub unbanned: bool,
}

#[utoipa::path(
    post,
    path = "/v1/admin/accounts/unban",
    operation_id = "admin_unban_account",
    tag = "admin",
    request_body = UnbanBody,
    responses(
        (status = 200, description = "已解除封禁（不自动恢复模板）", body = UnbanResponse),
        (status = 400, description = "email 与 key_id 必须二选一"),
        (status = 401, description = "密钥无效"),
        (status = 403, description = "没有 admin 权限"),
    )
)]
pub async fn unban_account(
    State(state): State<AppState>,
    ctx: RequestContext,
    body: Result<Json<UnbanBody>, JsonRejection>,
) -> Result<Json<UnbanResponse>, ApiError> {
    ctx.require_admin()?;
    ctx.check_read_limit(&state)?;
    let Json(body) = body.map_err(|rejection| map_json_rejection(&rejection))?;
    let email_hmac = resolve_email_hmac(&state, body.email.as_deref(), body.key_id).await?;
    Ok(Json(UnbanResponse {
        unbanned: accounts::unban(&state.pool, &email_hmac).await?,
    }))
}
