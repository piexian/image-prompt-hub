//! 需要密钥的写接口：上传、导入、修改、删除、我的模板。

use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::api::helpers::{if_match_ok, map_json_rejection, template_etag, RequestContext};
use crate::crypto;
use crate::error::ApiError;
use crate::models::{OwnedTemplateJson, TemplateJson, TemplateRow};
use crate::search::IndexOp;
use crate::state::AppState;
use crate::validate::{validate_upsert, TemplateUpsert};

/// ID 撞上主键时不报错、不返回行，由调用方换 ID 重试（报错会让事务进入失败状态）。
const INS_TEMPLATE: &str = "INSERT INTO templates (id, name, ai_description, content, defaults, reference, tags, author, owner_key_id, owner_email_hmac) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (id) DO NOTHING RETURNING id, name, ai_description, content, defaults, reference, tags, author, owner_key_id, owner_email_hmac, status, version, created_at, updated_at";
const SEL_TEMPLATE_BY_ID: &str = "SELECT id, name, ai_description, content, defaults, reference, tags, author, owner_key_id, owner_email_hmac, status, version, created_at, updated_at FROM templates WHERE id = $1 AND status <> 'deleted'";
const UPD_TEMPLATE: &str = "UPDATE templates SET name = $2, ai_description = $3, content = $4, defaults = $5, reference = $6, tags = $7, author = $8, version = version + 1, updated_at = now() WHERE id = $1 AND version = $9 AND status <> 'deleted' RETURNING id, name, ai_description, content, defaults, reference, tags, author, owner_key_id, owner_email_hmac, status, version, created_at, updated_at";
const SEL_MY_TEMPLATES: &str = "SELECT id, name, ai_description, content, defaults, reference, tags, author, owner_key_id, owner_email_hmac, status, version, created_at, updated_at FROM templates WHERE owner_email_hmac = $1 AND status <> 'deleted' ORDER BY updated_at DESC";

const IMPORT_MAX_ITEMS: usize = 50;

/// 新建 ID 撞主键时的最多尝试次数。
const ID_ATTEMPTS: usize = 3;

/// 配额检查失败的类型：新建额度用 429，总数上限用 403。
pub enum QuotaError {
    CreatePerHour { retry_after_secs: u64 },
    TemplateLimit,
}

impl QuotaError {
    pub fn to_api_error(&self) -> ApiError {
        match self {
            Self::CreatePerHour { retry_after_secs } => {
                let mut error = ApiError::new(
                    crate::error::ErrorCode::RateLimited,
                    "账号每小时新建模板数已达上限，请稍后再试",
                );
                error.retry_after = Some(*retry_after_secs);
                error
            }
            Self::TemplateLimit => ApiError::new(
                crate::error::ErrorCode::Forbidden,
                "账号模板总数已达上限，请先删除一些模板",
            ),
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::CreatePerHour { .. } => "账号每小时新建模板数已达上限，请稍后再试".to_string(),
            Self::TemplateLimit => "账号模板总数已达上限，请先删除一些模板".to_string(),
        }
    }
}

/// 按账号检查两项写入额度：每小时新建条数（含已删除的，避免删了再建绕过）与未删除模板总数。
async fn account_quota_violation(
    conn: &mut sqlx::PgConnection,
    config: &crate::config::Config,
    owner_email_hmac: &str,
) -> Result<Option<QuotaError>, ApiError> {
    // 同时取出窗口内最早一条的剩余时间，作为 Retry-After（最早一个名额释放的时刻）
    let (created_last_hour, seconds_until_slot): (i64, i64) = sqlx::query_as(
        "SELECT count(*),
                GREATEST(COALESCE(ceil(extract(epoch FROM (min(created_at) + interval '1 hour' - now()))), 1), 1)::bigint
         FROM templates
         WHERE owner_email_hmac = $1 AND created_at > now() - interval '1 hour'",
    )
    .bind(owner_email_hmac)
    .fetch_one(&mut *conn)
    .await?;
    if created_last_hour >= i64::from(config.account_create_per_hour) {
        return Ok(Some(QuotaError::CreatePerHour {
            retry_after_secs: seconds_until_slot as u64,
        }));
    }
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM templates WHERE owner_email_hmac = $1 AND status <> 'deleted'",
    )
    .bind(owner_email_hmac)
    .fetch_one(&mut *conn)
    .await?;
    if total >= i64::from(config.account_template_limit) {
        return Ok(Some(QuotaError::TemplateLimit));
    }
    Ok(None)
}

/// 新建结果：创建成功，或被账号额度拒绝。
pub enum CreateOutcome {
    Created(Box<TemplateRow>),
    QuotaExceeded(QuotaError),
}

/// 检查账号额度并插入模板。额度检查与插入在同一个事务里，并先取账号级咨询锁，
/// 同一账号的并发请求按顺序检查，不会同时通过额度后一起写入。
/// ID 撞上主键时换一个 ID 重试，最多 `ID_ATTEMPTS` 次。
pub async fn create_template_row(
    state: &AppState,
    validated: &crate::validate::ValidatedTemplate,
    owner: &crate::models::ApiKeyRow,
    mut next_id: impl FnMut() -> String,
) -> Result<CreateOutcome, ApiError> {
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(format!("quota:{}", owner.email_hmac))
        .execute(&mut *tx)
        .await?;
    if let Some(quota) = account_quota_violation(&mut tx, &state.config, &owner.email_hmac).await? {
        // 立即回滚以释放账号锁，不等连接归还连接池
        tx.rollback().await?;
        return Ok(CreateOutcome::QuotaExceeded(quota));
    }
    for _ in 0..ID_ATTEMPTS {
        let row: Option<TemplateRow> = sqlx::query_as(INS_TEMPLATE)
            .bind(next_id())
            .bind(&validated.name)
            .bind(&validated.ai_description)
            .bind(&validated.content)
            .bind(&validated.defaults)
            .bind(&validated.reference)
            .bind(&validated.tags)
            .bind(&validated.author)
            .bind(owner.id)
            .bind(&owner.email_hmac)
            .fetch_optional(&mut *tx)
            .await?;
        if let Some(row) = row {
            tx.commit().await?;
            state.index.submit(IndexOp::Upsert(row.id.clone()));
            state.catalog.mark_dirty();
            return Ok(CreateOutcome::Created(Box::new(row)));
        }
        tracing::warn!("模板 ID 主键冲突，换 ID 重试");
    }
    tx.rollback().await?;
    Err(ApiError::internal_with("模板 ID 连续冲突，请重试"))
}

#[utoipa::path(
    post,
    path = "/v1/templates",
    operation_id = "create_template",
    tag = "write",
    request_body = TemplateUpsertDoc,
    responses(
        (status = 201, description = "上传成功，直接公开", body = TemplateJson),
        (status = 400, description = "字段校验失败"),
        (status = 401, description = "密钥无效"),
        (status = 403, description = "没有 write 权限"),
        (status = 413, description = "请求体过大"),
        (status = 429, description = "请求过于频繁"),
    )
)]
pub async fn create_template(
    State(state): State<AppState>,
    ctx: RequestContext,
    body: Result<Json<TemplateUpsert>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let key = ctx.require_write()?;
    state.limits.check_write(&key.id.to_string())?;
    let body = body.map_err(|rejection| map_json_rejection(&rejection))?;
    let validated = validate_upsert(&body).map_err(ApiError::bad_request)?;
    match create_template_row(&state, &validated, key, crypto::generate_template_id).await? {
        CreateOutcome::Created(row) => {
            Ok((StatusCode::CREATED, Json(TemplateJson::from(*row))).into_response())
        }
        CreateOutcome::QuotaExceeded(quota) => Err(quota.to_api_error()),
    }
}

/// 文档用的请求体说明（与 TemplateUpsert 同构，避免暴露内部结构）。
#[derive(Debug, Serialize, ToSchema)]
pub struct TemplateUpsertDoc {
    pub name: String,
    pub ai_description: Option<String>,
    pub content: String,
    #[schema(value_type = Object)]
    pub defaults: Option<Value>,
    pub reference: Option<String>,
    pub tags: Option<Vec<String>>,
    pub author: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ImportItem {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub ai_description: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub defaults: Option<Value>,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub nsfw: Option<bool>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub version: Option<i64>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

impl ImportItem {
    /// 包内自带的服务端字段一律忽略，转成与上传相同的校验输入。
    fn to_upsert(&self) -> TemplateUpsert {
        TemplateUpsert {
            name: self.name.clone(),
            ai_description: self.ai_description.clone(),
            content: self.content.clone(),
            defaults: self.defaults.clone(),
            reference: self.reference.clone(),
            tags: self.tags.clone(),
            author: self.author.clone(),
            nsfw: self.nsfw,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ImportPackage {
    pub format: String,
    pub version: u32,
    #[serde(default)]
    pub templates: Vec<ImportItem>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(untagged)]
pub enum ImportResultItem {
    Ok { index: usize, id: String },
    Err { index: usize, error: String },
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImportResponse {
    pub results: Vec<ImportResultItem>,
}

#[utoipa::path(
    post,
    path = "/v1/templates/import",
    operation_id = "import_templates",
    tag = "write",
    request_body(content = Value, description = "JSON 包：{\"format\":\"gemini-image-templates\",\"version\":1,\"templates\":[...]}，最多 50 条"),
    responses(
        (status = 200, description = "逐条导入结果（部分成功）", body = ImportResponse),
        (status = 400, description = "包格式错误或条数超限"),
        (status = 401, description = "密钥无效"),
        (status = 403, description = "没有 write 权限"),
        (status = 413, description = "请求体超过 1MB"),
        (status = 429, description = "请求过于频繁"),
    )
)]
pub async fn import_templates(
    State(state): State<AppState>,
    ctx: RequestContext,
    body: Result<Json<ImportPackage>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<ImportResponse>, ApiError> {
    let key = ctx.require_write()?;
    state.limits.check_write(&key.id.to_string())?;
    let axum::Json(package) = body.map_err(|rejection| map_json_rejection(&rejection))?;
    if package.format != crate::models::PACKAGE_FORMAT {
        return Err(ApiError::bad_request(
            "format 必须是 gemini-image-templates",
        ));
    }
    if package.version != crate::models::PACKAGE_VERSION {
        return Err(ApiError::bad_request("version 只支持 1"));
    }
    if package.templates.len() > IMPORT_MAX_ITEMS {
        return Err(ApiError::bad_request("单次最多导入 50 条"));
    }

    let mut results = Vec::with_capacity(package.templates.len());
    for (index, item) in package.templates.into_iter().enumerate() {
        let result = match validate_upsert(&item.to_upsert()) {
            // 每一条都计入额度，超出部分逐条报错
            Ok(validated) => {
                match create_template_row(&state, &validated, key, crypto::generate_template_id)
                    .await
                {
                    Ok(CreateOutcome::Created(row)) => ImportResultItem::Ok { index, id: row.id },
                    Ok(CreateOutcome::QuotaExceeded(quota)) => ImportResultItem::Err {
                        index,
                        error: quota.message(),
                    },
                    Err(error) => ImportResultItem::Err {
                        index,
                        error: error.message,
                    },
                }
            }
            Err(error) => ImportResultItem::Err { index, error },
        };
        results.push(result);
    }
    Ok(Json(ImportResponse { results }))
}

/// 带版本条件的更新：只有当前版本仍是读出时的版本才会写入。
/// 返回 `None` 表示读出之后已被别人改过（或已删除），调用方应返回 409。
pub async fn update_if_version(
    pool: &sqlx::PgPool,
    id: &str,
    validated: &crate::validate::ValidatedTemplate,
    expected_version: i64,
) -> Result<Option<TemplateRow>, ApiError> {
    Ok(sqlx::query_as(UPD_TEMPLATE)
        .bind(id)
        .bind(&validated.name)
        .bind(&validated.ai_description)
        .bind(&validated.content)
        .bind(&validated.defaults)
        .bind(&validated.reference)
        .bind(&validated.tags)
        .bind(&validated.author)
        .bind(expected_version)
        .fetch_optional(pool)
        .await?)
}

#[utoipa::path(
    put,
    path = "/v1/templates/{id}",
    operation_id = "update_template",
    tag = "write",
    params(("id" = String, Path, description = "模板 ID")),
    request_body = TemplateUpsertDoc,
    responses(
        (status = 200, description = "修改成功，version 加 1，返回新 ETag"),
        (status = 400, description = "字段校验失败"),
        (status = 401, description = "密钥无效"),
        (status = 403, description = "不是本人模板"),
        (status = 404, description = "模板不存在"),
        (status = 409, description = "If-Match 与当前版本不匹配"),
        (status = 429, description = "请求过于频繁"),
    )
)]
pub async fn update_template(
    State(state): State<AppState>,
    ctx: RequestContext,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    body: Result<Json<TemplateUpsert>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let key = ctx.require_write()?;
    state.limits.check_write(&key.id.to_string())?;
    let body = body.map_err(|rejection| map_json_rejection(&rejection))?;

    let existing: TemplateRow = sqlx::query_as(SEL_TEMPLATE_BY_ID)
        .bind(&id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(ApiError::not_found)?;

    // 归属按账号身份判断：重置密钥后仍能修改自己的模板
    if existing.owner_email_hmac != key.email_hmac && ctx.require_admin().is_err() {
        return Err(ApiError::forbidden());
    }
    let etag = template_etag(&existing.id, existing.version);
    if_match_ok(&headers, &etag)?;

    let validated = validate_upsert(&body).map_err(ApiError::bad_request)?;
    let Some(row) = update_if_version(&state.pool, &id, &validated, existing.version).await? else {
        return Err(ApiError::conflict("模板已被其他人修改，请刷新后重试"));
    };

    let is_published = row.status == "published";
    if is_published {
        state.index.submit(IndexOp::Upsert(row.id.clone()));
    }
    state.catalog.mark_dirty();

    let new_etag = template_etag(&row.id, row.version);
    let mut response = Json(TemplateJson::from(row)).into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&new_etag).expect("ETAG 可编码"),
    );
    Ok(response)
}

#[utoipa::path(
    delete,
    path = "/v1/templates/{id}",
    operation_id = "delete_template",
    tag = "write",
    params(("id" = String, Path, description = "模板 ID")),
    responses(
        (status = 204, description = "已标记删除"),
        (status = 401, description = "密钥无效"),
        (status = 403, description = "不是本人模板"),
        (status = 404, description = "模板不存在"),
        (status = 429, description = "请求过于频繁"),
    )
)]
pub async fn delete_template(
    State(state): State<AppState>,
    ctx: RequestContext,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let key = ctx.require_write()?;
    state.limits.check_write(&key.id.to_string())?;

    let owner_email_hmac: String = sqlx::query_scalar(
        "SELECT owner_email_hmac FROM templates WHERE id = $1 AND status <> 'deleted'",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(ApiError::not_found)?;
    if owner_email_hmac != key.email_hmac && ctx.require_admin().is_err() {
        return Err(ApiError::forbidden());
    }

    sqlx::query("UPDATE templates SET status = 'deleted', updated_at = now() WHERE id = $1")
        .bind(&id)
        .execute(&state.pool)
        .await?;
    state.index.submit(IndexOp::Delete(id));
    state.catalog.mark_dirty();
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MyTemplatesResponse {
    pub templates: Vec<OwnedTemplateJson>,
}

#[utoipa::path(
    get,
    path = "/v1/me/templates",
    operation_id = "my_templates",
    tag = "write",
    responses(
        (status = 200, description = "自己上传的模板（含 hidden，不含 deleted）", body = MyTemplatesResponse),
        (status = 401, description = "密钥无效"),
    )
)]
pub async fn my_templates(
    State(state): State<AppState>,
    ctx: RequestContext,
) -> Result<Json<MyTemplatesResponse>, ApiError> {
    ctx.check_read_limit(&state)?;
    let key = ctx.require_key()?;
    let rows: Vec<TemplateRow> = sqlx::query_as(SEL_MY_TEMPLATES)
        .bind(&key.email_hmac)
        .fetch_all(&state.pool)
        .await?;
    let templates = rows
        .into_iter()
        .map(|row| {
            let status = row.status.clone();
            OwnedTemplateJson {
                template: row.into(),
                status,
            }
        })
        .collect();
    Ok(Json(MyTemplatesResponse { templates }))
}
