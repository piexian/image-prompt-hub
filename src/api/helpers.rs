//! handler 共用工具：认证+限流的读检查、游标编解码、JSON 拒绝映射。

use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::auth::{bearer_token, client_ip, touch_last_used};
use crate::error::ApiError;
use crate::models::ApiKeyRow;
use crate::state::AppState;

/// 带认证上下文的请求提取器：
/// - 有 Bearer 密钥时先按 IP 扣认证尝试额度，再校验并加载（无效则 401）；
/// - 无密钥时按匿名 IP 处理。
///
/// 只保留 IP 的 HMAC，明文 IP 不离开提取器，避免被写进日志。
pub struct RequestContext {
    pub key: Option<ApiKeyRow>,
    pub ip_hash: String,
}

impl FromRequestParts<AppState> for RequestContext {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let addr = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0)
            .unwrap_or_else(|| "0.0.0.0:0".parse().expect("占位地址有效"));
        let ip = client_ip(&parts.headers, addr, state.config.trust_cf_connecting_ip);
        // 限流与哈希都用归并后的键（IPv6 按 /64），防止网段内轮换地址绕过
        let ip_key = crate::auth::rate_limit_key(&ip);
        let ip_hash = state.config.ip_hash(&ip_key);

        let key = match bearer_token(&parts.headers) {
            Some(token) => {
                // 查库前只读检查认证失败窗口：无效密钥洪泛在此被挡下，不查库
                state.limits.check_auth_failure(&ip_hash)?;
                match crate::auth::authenticate(&state.pool, &state.config.key_hash(&token)).await {
                    Ok(row) => {
                        touch_last_used(&state.pool, row.id, row.last_used_at).await;
                        Some(row)
                    }
                    // 认证失败（401）才计数；其他错误（如数据库故障）不计
                    Err(error) if error.code == crate::error::ErrorCode::Unauthorized => {
                        state.limits.record_auth_failure(&ip_hash);
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                }
            }
            None => None,
        };
        Ok(Self { key, ip_hash })
    }
}

impl RequestContext {
    /// 公开读接口限流：带密钥按密钥 ID，匿名按 IP 哈希。
    pub fn check_read_limit(&self, state: &AppState) -> Result<(), ApiError> {
        match &self.key {
            Some(key) => state.limits.check_keyed_read(&key.id.to_string()),
            None => state.limits.check_anon_read(&self.ip_hash),
        }
    }

    /// 需要密钥：匿名或非 active 返回 401。
    pub fn require_key(&self) -> Result<&ApiKeyRow, ApiError> {
        self.key.as_ref().ok_or_else(ApiError::unauthorized)
    }

    /// 需要 write 或 admin 权限。
    pub fn require_write(&self) -> Result<&ApiKeyRow, ApiError> {
        let key = self.require_key()?;
        if key.scopes.iter().any(|s| s == "write" || s == "admin") {
            Ok(key)
        } else {
            Err(ApiError::forbidden())
        }
    }

    /// 需要 admin 权限。
    pub fn require_admin(&self) -> Result<&ApiKeyRow, ApiError> {
        let key = self.require_key()?;
        if key.scopes.iter().any(|s| s == "admin") {
            Ok(key)
        } else {
            Err(ApiError::forbidden())
        }
    }
}

/// 不透明游标。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cursor {
    /// 列表：(updated_at, id)
    List { u: String, i: String },
    /// 检索：offset
    Search { o: u32 },
}

pub fn encode_cursor(cursor: &Cursor) -> String {
    let json = serde_json::to_string(cursor).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(json)
}

pub fn decode_cursor(raw: &str) -> Result<Cursor, ApiError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| ApiError::bad_request("cursor 不是有效的编码"))?;
    let cursor: Cursor = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::bad_request("cursor 不是有效的编码"))?;
    // 列表游标的时间在这里就解析，非法值返回 400 而不是让数据库报转换错误
    if let Cursor::List { u, .. } = &cursor {
        parse_cursor_time(u)?;
    }
    Ok(cursor)
}

/// 解析列表游标里的时间，查询时以带类型的值绑定，数据库不再做文本转换。
pub fn parse_cursor_time(raw: &str) -> Result<DateTime<Utc>, ApiError> {
    DateTime::parse_from_rfc3339(raw)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| ApiError::bad_request("cursor 里的时间无效"))
}

/// JSON 提取失败的统一映射：超限 → payload_too_large，其余 → bad_request。
pub fn map_json_rejection(rejection: &JsonRejection) -> ApiError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::payload_too_large()
    } else {
        ApiError::bad_request(format!("请求体不是有效的 JSON：{}", rejection.body_text()))
    }
}

/// 解析 limit 参数：默认值、上限、下限，非法值一律 400。
pub fn parse_limit(raw: &Option<String>, default: usize, max: usize) -> Result<usize, ApiError> {
    match raw {
        None => Ok(default),
        Some(value) => {
            let parsed: usize = value
                .trim()
                .parse()
                .map_err(|_| ApiError::bad_request("limit 必须是正整数"))?;
            if parsed == 0 || parsed > max {
                Err(ApiError::bad_request(format!(
                    "limit 必须在 1 到 {max} 之间"
                )))
            } else {
                Ok(parsed)
            }
        }
    }
}

/// 模板详情 ETag：`"id-vN"`。
pub fn template_etag(id: &str, version: i64) -> String {
    format!("\"{id}-v{version}\"")
}

/// If-None-Match 命中判断（容忍 W/ 前缀、引号与多值）。
pub fn if_none_match_hits(header: &HeaderMap, etag: &str) -> bool {
    header
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(|tag| tag.trim().trim_start_matches("W/"))
                .any(|tag| tag == etag || tag == "*")
        })
        .unwrap_or(false)
}

/// If-Match 校验：带头部但不匹配时返回 409。
pub fn if_match_ok(header: &HeaderMap, etag: &str) -> Result<(), ApiError> {
    match header
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        None => Ok(()),
        Some(value) => {
            let hit = value
                .split(',')
                .map(|tag| tag.trim().trim_start_matches("W/"))
                .any(|tag| tag == etag);
            if hit {
                Ok(())
            } else {
                Err(ApiError::conflict("If-Match 与当前版本不匹配"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn cursor_roundtrip() {
        let cursor = Cursor::List {
            u: "2026-01-01T00:00:00Z".into(),
            i: "abc".into(),
        };
        let encoded = encode_cursor(&cursor);
        assert!(matches!(
            decode_cursor(&encoded).unwrap(),
            Cursor::List { .. }
        ));
        let search = Cursor::Search { o: 40 };
        assert_eq!(decode_cursor(&encode_cursor(&search)).unwrap(), search);
        assert!(decode_cursor("!!!").is_err());
        assert!(decode_cursor("aGVsbG8").is_err()); // 合法 base64 但不是游标 JSON
                                                    // 列表游标时间非法 → 400（不进数据库）
        let bad_time = encode_cursor(&Cursor::List {
            u: "not-a-time".into(),
            i: "abc".into(),
        });
        assert!(decode_cursor(&bad_time).is_err());
        // 合法的 RFC 3339 时间解析为 UTC 时刻
        let parsed = parse_cursor_time("2026-10-30T21:28:54.977612+08:00").unwrap();
        assert_eq!(parsed.to_rfc3339(), "2026-10-30T13:28:54.977612+00:00");
        assert!(parse_cursor_time("2026-13-40T00:00:00Z").is_err());
        assert!(parse_cursor_time("").is_err());
    }

    #[test]
    fn limit_parsing() {
        assert_eq!(parse_limit(&None, 20, 50).unwrap(), 20);
        assert_eq!(parse_limit(&Some("5".into()), 20, 50).unwrap(), 5);
        assert!(parse_limit(&Some("0".into()), 20, 50).is_err());
        assert!(parse_limit(&Some("51".into()), 20, 50).is_err());
        assert!(parse_limit(&Some("abc".into()), 20, 50).is_err());
        assert!(parse_limit(&Some("-1".into()), 20, 50).is_err());
    }

    #[test]
    fn etag_matching() {
        let mut headers = HeaderMap::new();
        let etag = template_etag("abc", 3);
        assert_eq!(etag, "\"abc-v3\"");
        headers.insert(
            axum::http::header::IF_NONE_MATCH,
            "\"xyz-v1\"".parse().unwrap(),
        );
        assert!(!if_none_match_hits(&headers, &etag));
        headers.insert(
            axum::http::header::IF_NONE_MATCH,
            "W/\"abc-v3\", \"other\"".parse().unwrap(),
        );
        assert!(if_none_match_hits(&headers, &etag));
        headers.insert(axum::http::header::IF_NONE_MATCH, "*".parse().unwrap());
        assert!(if_none_match_hits(&headers, &etag));

        headers.remove(axum::http::header::IF_NONE_MATCH);
        assert!(if_match_ok(&headers, &etag).is_ok());
        headers.insert(axum::http::header::IF_MATCH, "\"old-v1\"".parse().unwrap());
        assert!(if_match_ok(&headers, &etag).is_err());
        headers.insert(axum::http::header::IF_MATCH, "\"abc-v3\"".parse().unwrap());
        assert!(if_match_ok(&headers, &etag).is_ok());
    }
}
