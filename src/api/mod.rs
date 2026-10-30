//! HTTP 接口：路由、公共中间件与各分组 handler。

pub mod admin;
pub mod docs;
pub mod helpers;
pub mod keys;
pub mod public;
pub mod write;

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get, post, put};
use axum::Router;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;

use crate::error::ApiError;
use crate::state::AppState;

pub const DEFAULT_BODY_LIMIT: usize = 256 * 1024;
pub const IMPORT_BODY_LIMIT: usize = 1024 * 1024;

/// 缓存策略：默认一律 no-store；只有明确公开的只读接口的成功响应（200/304）
/// 允许共享缓存，错误响应与写操作永不缓存；带 Authorization 头的请求一律 private, no-store。
fn cache_policy(method: &Method, path: &str, status: StatusCode, has_auth: bool) -> &'static str {
    if has_auth {
        return "private, no-store";
    }
    let readable = matches!(*method, Method::GET | Method::HEAD);
    if !readable || !matches!(status, StatusCode::OK | StatusCode::NOT_MODIFIED) {
        return "no-store";
    }
    match path {
        "/v1/catalog" => "public, max-age=300",
        "/v1/catalog/version"
        | "/v1/templates"
        | "/v1/templates/batch"
        | "/v1/tags"
        | "/v1/status"
        | "/openapi.json"
        | "/llms.txt" => "public, max-age=60",
        // 模板详情 /v1/templates/{id}（单段路径）
        _ if path
            .strip_prefix("/v1/templates/")
            .is_some_and(|id| !id.is_empty() && !id.contains('/')) =>
        {
            "public, max-age=60"
        }
        _ => "no-store",
    }
}

async fn cache_control(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let has_auth = request.headers().contains_key(header::AUTHORIZATION);
    let mut response = next.run(request).await;
    let value = cache_policy(&method, &path, response.status(), has_auth);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(value));
    response
}

/// 未匹配任何路由时返回统一的 JSON 错误。
async fn not_found_fallback() -> ApiError {
    ApiError::not_found()
}

/// 访问日志：只记方法、路径（不含查询串）、状态与耗时。
async fn access_log(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let start = std::time::Instant::now();
    let response = next.run(request).await;
    tracing::info!(
        method = %method,
        path = %path,
        status = response.status().as_u16(),
        ms = start.elapsed().as_millis() as u64,
        "access"
    );
    response
}

pub fn router(state: AppState) -> Router {
    let import_route =
        post(write::import_templates).layer(DefaultBodyLimit::max(IMPORT_BODY_LIMIT));

    Router::new()
        // 公开只读
        .route(
            "/v1/templates",
            get(public::list_templates).post(write::create_template),
        )
        .route("/v1/templates/batch", get(public::batch_templates))
        .route("/v1/templates/{id}", get(public::get_template))
        .route("/v1/templates/{id}/report", post(public::report_template))
        .route("/v1/tags", get(public::list_tags))
        .route("/v1/status", get(public::status))
        .route("/v1/catalog/version", get(public::catalog_version))
        .route("/v1/catalog", get(public::catalog))
        // 文档
        .route("/openapi.json", get(docs::openapi_json))
        .route("/llms.txt", get(docs::llms_txt))
        // 密钥申请与验证
        .route("/v1/keys/request", post(keys::request_key))
        .route(
            "/v1/keys/verify",
            get(keys::verify_page).post(keys::verify_confirm),
        )
        // 需要密钥
        .route("/v1/key", get(keys::key_info).delete(keys::revoke_own_key))
        .route("/v1/templates/import", import_route)
        .route("/v1/me/templates", get(write::my_templates))
        .route(
            "/v1/templates/{id}",
            put(write::update_template).delete(write::delete_template),
        )
        .route("/v1/admin/reports", get(admin::list_reports))
        .route("/v1/admin/templates/{id}/hide", post(admin::hide_template))
        .route(
            "/v1/admin/templates/{id}/restore",
            post(admin::restore_template),
        )
        .route("/v1/admin/keys/lookup", post(admin::lookup_keys_by_email))
        .route("/v1/admin/accounts/ban", post(admin::ban_account))
        .route("/v1/admin/accounts/unban", post(admin::unban_account))
        .route("/v1/admin/keys/{key_id}", delete(admin::revoke_key))
        .fallback(not_found_fallback)
        // 由内向外：请求体上限 → 超时 → 访问日志 → nosniff → 缓存策略。
        // 缓存策略与 nosniff 在最外层，超时（408）、未匹配路由等响应也带这些头。
        .layer(DefaultBodyLimit::max(DEFAULT_BODY_LIMIT))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(10),
        ))
        .layer(middleware::from_fn(access_log))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(middleware::from_fn(cache_control))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(method: Method, path: &str, status: u16, auth: bool) -> &'static str {
        cache_policy(&method, path, StatusCode::from_u16(status).unwrap(), auth)
    }

    #[test]
    fn public_read_endpoints_are_cacheable_on_success_only() {
        for (path, expected) in [
            ("/v1/catalog", "public, max-age=300"),
            ("/v1/catalog/version", "public, max-age=60"),
            ("/v1/templates", "public, max-age=60"),
            ("/v1/templates/batch", "public, max-age=60"),
            ("/v1/templates/abcdefghijk2", "public, max-age=60"),
            ("/v1/tags", "public, max-age=60"),
            ("/v1/status", "public, max-age=60"),
            ("/openapi.json", "public, max-age=60"),
            ("/llms.txt", "public, max-age=60"),
        ] {
            assert_eq!(policy(Method::GET, path, 200, false), expected, "{path}");
            assert_eq!(policy(Method::HEAD, path, 200, false), expected, "{path}");
            assert_eq!(
                policy(Method::GET, path, 304, false),
                expected,
                "{path} 304"
            );
            // 错误响应不进共享缓存
            for status in [400, 404, 429, 500] {
                assert_eq!(policy(Method::GET, path, status, false), "no-store");
            }
        }
    }

    #[test]
    fn everything_else_is_no_store() {
        for (method, path) in [
            (Method::POST, "/v1/templates"),
            (Method::POST, "/v1/templates/import"),
            (Method::POST, "/v1/templates/abcdefghijk2/report"),
            (Method::PUT, "/v1/templates/abcdefghijk2"),
            (Method::DELETE, "/v1/templates/abcdefghijk2"),
            (Method::GET, "/v1/me/templates"),
            (Method::GET, "/v1/key"),
            (Method::GET, "/v1/keys/verify"),
            (Method::POST, "/v1/keys/request"),
            (Method::GET, "/v1/admin/reports"),
            (Method::GET, "/v1/templates/abcdefghijk2/report"),
            (Method::GET, "/v1/templates/"),
            (Method::GET, "/no-such-route"),
        ] {
            assert_eq!(
                policy(method.clone(), path, 200, false),
                "no-store",
                "{method} {path}"
            );
        }
    }

    #[test]
    fn requests_with_authorization_are_private() {
        for (path, status) in [("/v1/status", 200), ("/v1/catalog", 200), ("/v1/key", 401)] {
            assert_eq!(policy(Method::GET, path, status, true), "private, no-store");
        }
        assert_eq!(
            policy(Method::POST, "/v1/templates", 201, true),
            "private, no-store"
        );
    }
}
