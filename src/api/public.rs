//! 公开只读接口与目录快照下载。

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::helpers::{
    decode_cursor, encode_cursor, if_none_match_hits, parse_cursor_time, parse_limit,
    template_etag, Cursor, RequestContext,
};
use crate::error::ApiError;
use crate::models::{TemplateJson, TemplateRow};
use crate::search::SEARCH_OFFSET_LIMIT;
use crate::state::AppState;
use crate::validate::has_forbidden_control;

const SEL_PUBLISHED_BY_IDS: &str = "SELECT id, name, ai_description, content, defaults, reference, tags, author, owner_key_id, owner_email_hmac, status, version, created_at, updated_at FROM templates WHERE status = 'published' AND id = ANY($1)";
const SEL_PUBLISHED_BY_ID: &str = "SELECT id, name, ai_description, content, defaults, reference, tags, author, owner_key_id, owner_email_hmac, status, version, created_at, updated_at FROM templates WHERE id = $1 AND status = 'published'";
const SEL_PUBLISHED_TAG_CURSOR: &str = "SELECT id, name, ai_description, content, defaults, reference, tags, author, owner_key_id, owner_email_hmac, status, version, created_at, updated_at FROM templates WHERE status = 'published' AND $1 = ANY(tags) AND (updated_at, id) < (COALESCE($2::timestamptz, 'infinity'), COALESCE($3::text, '')) ORDER BY updated_at DESC, id DESC LIMIT $4";
const SEL_PUBLISHED_CURSOR: &str = "SELECT id, name, ai_description, content, defaults, reference, tags, author, owner_key_id, owner_email_hmac, status, version, created_at, updated_at FROM templates WHERE status = 'published' AND (updated_at, id) < (COALESCE($1::timestamptz, 'infinity'), COALESCE($2::text, '')) ORDER BY updated_at DESC, id DESC LIMIT $3";

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListParams {
    pub q: Option<String>,
    pub tag: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListEntry {
    #[serde(flatten)]
    pub template: TemplateJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListResponse {
    pub templates: Vec<ListEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// 检索关键词上限。
const QUERY_MAX_CHARS: usize = 100;

#[utoipa::path(
    get,
    path = "/v1/templates",
    operation_id = "list_templates",
    tag = "templates",
    params(ListParams),
    responses(
        (status = 200, description = "模板列表；带 q 走 BM25 检索并附 snippet，否则按更新时间倒序", body = ListResponse),
        (status = 400, description = "参数无效"),
        (status = 401, description = "密钥无效"),
        (status = 429, description = "请求过于频繁"),
    )
)]
pub async fn list_templates(
    State(state): State<AppState>,
    ctx: RequestContext,
    Query(params): Query<ListParams>,
) -> Result<Json<ListResponse>, ApiError> {
    ctx.check_read_limit(&state)?;
    let limit = parse_limit(&params.limit, 20, 50)?;

    if let Some(q) = params.q.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
        if q.chars().count() > QUERY_MAX_CHARS {
            return Err(ApiError::bad_request("q 最长 100 字"));
        }
        let offset = match params.cursor.as_deref() {
            None => 0usize,
            Some(raw) => match decode_cursor(raw)? {
                Cursor::Search { o } => o as usize,
                _ => return Err(ApiError::bad_request("cursor 与当前列表模式不匹配")),
            },
        };
        let outcome = state.index.search(
            q,
            params.tag.as_deref().filter(|t| !t.is_empty()),
            offset,
            limit,
        )?;
        let ids: Vec<String> = outcome.hits.iter().map(|(id, _)| id.clone()).collect();
        let rows: Vec<TemplateRow> = if ids.is_empty() {
            Vec::new()
        } else {
            sqlx::query_as(SEL_PUBLISHED_BY_IDS)
                .bind(&ids)
                .fetch_all(&state.pool)
                .await?
        };
        let mut entries: Vec<ListEntry> = Vec::with_capacity(rows.len());
        for (id, _) in &outcome.hits {
            if let Some(row) = rows.iter().find(|row| &row.id == id) {
                entries.push(ListEntry {
                    template: row.clone().into(),
                    snippet: outcome.snippet(&row.content),
                });
            }
        }
        // 以索引命中数判断是否还有下一页：个别命中在库里已非 published 时 entries 会偏少
        let next_cursor = if outcome.hits.len() == limit && offset + limit < SEARCH_OFFSET_LIMIT {
            Some(encode_cursor(&Cursor::Search {
                o: (offset + limit) as u32,
            }))
        } else {
            None
        };
        Ok(Json(ListResponse {
            templates: entries,
            next_cursor,
        }))
    } else {
        let (cursor_updated, cursor_id) = match params.cursor.as_deref() {
            None => (None, None),
            Some(raw) => match decode_cursor(raw)? {
                Cursor::List { u, i } => (Some(parse_cursor_time(&u)?), Some(i)),
                _ => return Err(ApiError::bad_request("cursor 与当前列表模式不匹配")),
            },
        };
        // 是否带 tag 精确过滤决定用哪个静态查询
        let rows: Vec<TemplateRow> =
            if let Some(tag) = params.tag.as_deref().filter(|t| !t.is_empty()) {
                sqlx::query_as(SEL_PUBLISHED_TAG_CURSOR)
                    .bind(tag)
                    .bind(cursor_updated)
                    .bind(cursor_id.as_deref())
                    .bind(limit as i64)
                    .fetch_all(&state.pool)
                    .await?
            } else {
                sqlx::query_as(SEL_PUBLISHED_CURSOR)
                    .bind(cursor_updated)
                    .bind(cursor_id.as_deref())
                    .bind(limit as i64)
                    .fetch_all(&state.pool)
                    .await?
            };
        let next_cursor = if rows.len() == limit {
            let last = rows.last().expect("rows 非空");
            Some(encode_cursor(&Cursor::List {
                u: last.updated_at.to_rfc3339(),
                i: last.id.clone(),
            }))
        } else {
            None
        };
        let templates = rows
            .into_iter()
            .map(|row| ListEntry {
                template: row.into(),
                snippet: None,
            })
            .collect();
        Ok(Json(ListResponse {
            templates,
            next_cursor,
        }))
    }
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct BatchParams {
    pub ids: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BatchResponse {
    pub templates: Vec<TemplateJson>,
}

#[utoipa::path(
    get,
    path = "/v1/templates/batch",
    operation_id = "batch_templates",
    tag = "templates",
    params(BatchParams),
    responses(
        (status = 200, description = "按 ids 返回找到的已公开模板（最多 50 个）", body = BatchResponse),
        (status = 400, description = "ids 参数无效"),
    )
)]
pub async fn batch_templates(
    State(state): State<AppState>,
    ctx: RequestContext,
    Query(params): Query<BatchParams>,
) -> Result<Json<BatchResponse>, ApiError> {
    ctx.check_read_limit(&state)?;
    let ids: Vec<String> = params
        .ids
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if ids.is_empty() {
        return Err(ApiError::bad_request("ids 不能为空"));
    }
    if ids.len() > 50 {
        return Err(ApiError::bad_request("ids 最多 50 个"));
    }
    let rows: Vec<TemplateRow> = sqlx::query_as(SEL_PUBLISHED_BY_IDS)
        .bind(&ids)
        .fetch_all(&state.pool)
        .await?;
    let mut templates = Vec::with_capacity(rows.len());
    for id in &ids {
        if let Some(row) = rows.iter().find(|row| &row.id == id) {
            templates.push(row.clone().into());
        }
    }
    Ok(Json(BatchResponse { templates }))
}

#[utoipa::path(
    get,
    path = "/v1/templates/{id}",
    operation_id = "get_template",
    tag = "templates",
    params(("id" = String, Path, description = "模板 ID")),
    responses(
        (status = 200, description = "模板详情，带 ETag，支持 If-None-Match 返回 304"),
        (status = 304, description = "内容未变化"),
        (status = 404, description = "模板不存在"),
    )
)]
pub async fn get_template(
    State(state): State<AppState>,
    ctx: RequestContext,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    ctx.check_read_limit(&state)?;
    let row: TemplateRow = sqlx::query_as(SEL_PUBLISHED_BY_ID)
        .bind(&id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(ApiError::not_found)?;

    let etag = template_etag(&row.id, row.version);
    if if_none_match_hits(&headers, &etag) {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        response.headers_mut().insert(
            header::ETAG,
            HeaderValue::from_str(&etag).expect("ETAG 可编码"),
        );
        return Ok(response);
    }
    let mut response = Json(TemplateJson::from(row)).into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&etag).expect("ETAG 可编码"),
    );
    Ok(response)
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct TagsParams {
    pub q: Option<String>,
    pub limit: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TagCount {
    pub tag: String,
    pub count: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TagsResponse {
    pub tags: Vec<TagCount>,
}

#[utoipa::path(
    get,
    path = "/v1/tags",
    operation_id = "list_tags",
    tag = "templates",
    params(TagsParams),
    responses(
        (status = 200, description = "标签与模板数，按数量倒序", body = TagsResponse),
    )
)]
pub async fn list_tags(
    State(state): State<AppState>,
    ctx: RequestContext,
    Query(params): Query<TagsParams>,
) -> Result<Json<TagsResponse>, ApiError> {
    ctx.check_read_limit(&state)?;
    let limit = parse_limit(&params.limit, 50, 200)?;
    let q = params.q.clone().unwrap_or_default();
    if q.chars().count() > 20 {
        return Err(ApiError::bad_request("q 最长 20 字"));
    }
    // LIKE 模式里的 %、_、\ 按字面量转义
    let escaped = q
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let pattern = format!("%{escaped}%");
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT t.tag, count(*)::bigint AS count
         FROM templates, unnest(tags) AS t(tag)
         WHERE status = 'published' AND t.tag ILIKE $1
         GROUP BY t.tag
         ORDER BY count(*) DESC, t.tag ASC
         LIMIT $2",
    )
    .bind(pattern)
    .bind(limit as i64)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(TagsResponse {
        tags: rows
            .into_iter()
            .map(|(tag, count)| TagCount { tag, count })
            .collect(),
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StatusResponse {
    pub version: String,
    pub template_count: i64,
    pub catalog: Option<crate::catalog::CatalogMeta>,
    pub rate_limits: serde_json::Value,
    #[schema(value_type = String)]
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

#[utoipa::path(
    get,
    path = "/v1/status",
    operation_id = "status",
    tag = "meta",
    responses(
        (status = 200, description = "服务状态与公开限流说明", body = StatusResponse),
    )
)]
pub async fn status(
    State(state): State<AppState>,
    ctx: RequestContext,
) -> Result<Json<StatusResponse>, ApiError> {
    ctx.check_read_limit(&state)?;
    let template_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM templates WHERE status = 'published'")
            .fetch_one(&state.pool)
            .await?;
    let config = &state.config;
    let rate_limits = serde_json::json!({
        "anonymous_read_per_minute_per_ip": config.rate_limits.anon_read_per_min,
        "keyed_read_per_minute_per_key": config.rate_limits.keyed_read_per_min,
        "write_per_minute_per_key": config.rate_limits.write_per_min,
        "key_request_per_hour_per_ip": config.rate_limits.key_request_per_hour,
        "key_verify_per_hour_per_ip": config.rate_limits.key_verify_per_hour,
        "report_per_hour_per_ip": config.rate_limits.report_per_hour,
        "auth_attempt_per_minute_per_ip": config.rate_limits.auth_attempt_per_min,
        "account_create_per_hour": config.account_create_per_hour,
        "account_template_limit": config.account_template_limit,
    });
    Ok(Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        template_count,
        catalog: state.catalog.meta(),
        rate_limits,
        generated_at: chrono::Utc::now(),
    }))
}

#[utoipa::path(
    get,
    path = "/v1/catalog/version",
    operation_id = "catalog_version",
    tag = "catalog",
    responses(
        (status = 200, description = "目录快照版本信息"),
    )
)]
pub async fn catalog_version(
    State(state): State<AppState>,
    ctx: RequestContext,
) -> Result<Json<crate::catalog::CatalogMeta>, ApiError> {
    ctx.check_read_limit(&state)?;
    let snapshot = state
        .catalog
        .snapshot()
        .ok_or_else(|| ApiError::internal_with("目录快照尚未生成"))?;
    Ok(Json(snapshot.meta.clone()))
}

#[utoipa::path(
    get,
    path = "/v1/catalog",
    operation_id = "catalog",
    tag = "catalog",
    responses(
        (status = 200, description = "全部已公开模板的 gzip JSON 包，ETag 为目录哈希"),
        (status = 304, description = "快照未变化"),
    )
)]
pub async fn catalog(
    State(state): State<AppState>,
    ctx: RequestContext,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    ctx.check_read_limit(&state)?;
    // 只取一次快照：ETag 与正文必须来自同一次生成
    let snapshot = state
        .catalog
        .snapshot()
        .ok_or_else(|| ApiError::internal_with("目录快照尚未生成"))?;
    let etag = format!("\"{}\"", snapshot.meta.hash);
    let etag_value = HeaderValue::from_str(&etag).expect("ETAG 可编码");
    if if_none_match_hits(&headers, &etag) {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        response.headers_mut().insert(header::ETAG, etag_value);
        return Ok(response);
    }
    let mut response = snapshot.gzipped.clone().into_response();
    let response_headers = response.headers_mut();
    response_headers.insert(header::ETAG, etag_value);
    response_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(response)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReportBody {
    pub reason: String,
}

#[utoipa::path(
    post,
    path = "/v1/templates/{id}/report",
    operation_id = "report_template",
    tag = "templates",
    params(("id" = String, Path, description = "模板 ID")),
    request_body = ReportBody,
    responses(
        (status = 202, description = "举报已受理"),
        (status = 400, description = "理由为空或超过 500 字"),
        (status = 404, description = "模板不存在"),
        (status = 429, description = "请求过于频繁"),
    )
)]
pub async fn report_template(
    State(state): State<AppState>,
    ctx: RequestContext,
    Path(id): Path<String>,
    body: Result<Json<ReportBody>, axum::extract::rejection::JsonRejection>,
) -> Result<StatusCode, ApiError> {
    state.limits.check_report(&ctx.ip_hash)?;
    let body = body.map_err(|rejection| crate::api::helpers::map_json_rejection(&rejection))?;
    let reason = body.reason.trim().to_string();
    if reason.is_empty() {
        return Err(ApiError::bad_request("举报理由不能为空"));
    }
    if reason.chars().count() > 500 {
        return Err(ApiError::bad_request("举报理由不能超过 500 字"));
    }
    if has_forbidden_control(&reason) {
        return Err(ApiError::bad_request("举报理由不能包含控制字符"));
    }
    let exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM templates WHERE id = $1 AND status = 'published'")
            .bind(&id)
            .fetch_optional(&state.pool)
            .await?;
    if exists.is_none() {
        return Err(ApiError::not_found());
    }
    sqlx::query("INSERT INTO reports (template_id, reason, ip_hash) VALUES ($1, $2, $3)")
        .bind(&id)
        .bind(&reason)
        .bind(&ctx.ip_hash)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::ACCEPTED)
}
