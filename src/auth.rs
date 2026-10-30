//! Bearer 密钥认证与客户端 IP 提取。

use axum::http::{HeaderMap, HeaderValue};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiError;
use crate::models::ApiKeyRow;

#[derive(Debug, Clone)]
pub struct AuthKey {
    pub id: Uuid,
    pub email_hmac: String,
    pub scopes: Vec<String>,
}

impl AuthKey {
    pub fn can_write(&self) -> bool {
        self.scopes.iter().any(|s| s == "write" || s == "admin")
    }

    pub fn is_admin(&self) -> bool {
        self.scopes.iter().any(|s| s == "admin")
    }
}

/// 从 Authorization: Bearer 读取密钥并查库。密钥无效或非 active 一律返回 401。
pub async fn authenticate(pool: &PgPool, key_hash: &str) -> Result<ApiKeyRow, ApiError> {
    let row: Option<ApiKeyRow> = sqlx::query_as(
        "SELECT id, key_prefix, key_hash, email_hmac, scopes, status, created_at, revoked_at, last_used_at
         FROM api_keys WHERE key_hash = $1",
    )
    .bind(key_hash)
    .fetch_optional(pool)
    .await
    .map_err(ApiError::from)?;
    match row {
        Some(key) if key.status == "active" => Ok(key),
        _ => Err(ApiError::unauthorized()),
    }
}

/// 从请求头解析 Bearer 密钥原文。
pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value: &HeaderValue = headers.get(axum::http::header::AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?
        .trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// last_used_at 的节流写库：同一密钥 60 秒内只更新一次。
pub async fn touch_last_used(
    pool: &PgPool,
    key_id: Uuid,
    last_used_at: Option<chrono::DateTime<Utc>>,
) {
    let stale = match last_used_at {
        Some(at) => (Utc::now() - at).num_seconds() >= 60,
        None => true,
    };
    if stale {
        let _ = sqlx::query("UPDATE api_keys SET last_used_at = now() WHERE id = $1")
            .bind(key_id)
            .execute(pool)
            .await;
    }
}

/// 限流与哈希用的客户端键：IPv4 用完整地址，IPv6 归并到 /64 前缀，
/// 防止在同一网段轮换地址绕过限流。IPv4 映射地址（双栈监听时的 IPv4 客户端）
/// 按其 IPv4 地址计，否则所有 IPv4 客户端会落进同一个 /64 前缀。
pub fn rate_limit_key(ip: &str) -> String {
    let Ok(parsed) = ip.parse::<std::net::IpAddr>() else {
        return ip.to_string();
    };
    match parsed {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let [a, b, c, d, ..] = v6.segments();
                std::net::Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0).to_string()
            }
        },
    }
}

/// 客户端 IP：TRUST_CF_CONNECTING_IP 为真时优先取 CF-Connecting-IP，
/// 请求头必须能解析为合法 IP，否则退回连接地址。
pub fn client_ip(headers: &HeaderMap, addr: std::net::SocketAddr, trust_cf: bool) -> String {
    if trust_cf {
        if let Some(value) = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
        {
            let value = value.trim();
            if value.parse::<std::net::IpAddr>().is_ok() {
                return value.to_string();
            }
        }
    }
    addr.ip().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_parsing() {
        let mut headers = HeaderMap::new();
        assert!(bearer_token(&headers).is_none());
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("iph_abc123"),
        );
        assert!(bearer_token(&headers).is_none());
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer iph_abc123"),
        );
        assert_eq!(bearer_token(&headers).unwrap(), "iph_abc123");
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer   "),
        );
        assert!(bearer_token(&headers).is_none());
    }

    #[test]
    fn client_ip_selection() {
        let addr: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.7"));
        assert_eq!(client_ip(&headers, addr, true), "203.0.113.7");
        assert_eq!(client_ip(&headers, addr, false), "127.0.0.1");
        // 非法 CF 头退回连接地址
        let mut bad = HeaderMap::new();
        bad.insert("cf-connecting-ip", HeaderValue::from_static("not-an-ip"));
        assert_eq!(client_ip(&bad, addr, true), "127.0.0.1");
        bad.insert("cf-connecting-ip", HeaderValue::from_static(""));
        assert_eq!(client_ip(&bad, addr, true), "127.0.0.1");
        // IPv6 合法头
        let mut v6 = HeaderMap::new();
        v6.insert(
            "cf-connecting-ip",
            HeaderValue::from_static("2001:db8:1:2:3:4:5:6"),
        );
        let v6_addr: std::net::SocketAddr = "[::1]:9999".parse().unwrap();
        assert_eq!(client_ip(&v6, v6_addr, true), "2001:db8:1:2:3:4:5:6");
        let empty = HeaderMap::new();
        assert_eq!(client_ip(&empty, addr, true), "127.0.0.1");
    }

    #[test]
    fn ipv6_rate_limit_key_is_prefix() {
        assert_eq!(rate_limit_key("192.0.2.1"), "192.0.2.1");
        assert_eq!(
            rate_limit_key("2001:db8:1:2:3:4:5:6"),
            rate_limit_key("2001:db8:1:2:dead:beef:0:1"),
            "同一 /64 应共享限流键"
        );
        assert_ne!(
            rate_limit_key("2001:db8:1:2:3:4:5:6"),
            rate_limit_key("2001:db8:1:3:3:4:5:6"),
            "不同 /64 键应不同"
        );
        // 缩写写法与完整写法落在同一个键
        assert_eq!(
            rate_limit_key("2001:db8:1:2::1"),
            rate_limit_key("2001:0db8:0001:0002:ffff:ffff:ffff:ffff")
        );
    }

    #[test]
    fn ipv4_mapped_clients_keep_distinct_keys() {
        assert_eq!(rate_limit_key("::ffff:203.0.113.9"), "203.0.113.9");
        assert_ne!(
            rate_limit_key("::ffff:203.0.113.9"),
            rate_limit_key("::ffff:203.0.113.10")
        );
        assert_eq!(
            rate_limit_key("::ffff:203.0.113.9"),
            rate_limit_key("203.0.113.9")
        );
        // 无法解析的输入原样返回，不会 panic
        assert_eq!(rate_limit_key("not-an-ip"), "not-an-ip");
    }

    #[test]
    fn scope_checks() {
        let key = AuthKey {
            id: Uuid::new_v4(),
            email_hmac: "hmac".to_string(),
            scopes: vec!["read".to_string()],
        };
        assert!(!key.can_write());
        let writer = AuthKey {
            scopes: vec!["write".into()],
            ..key.clone()
        };
        assert!(writer.can_write());
        assert!(!writer.is_admin());
        let admin = AuthKey {
            scopes: vec!["admin".into()],
            ..key
        };
        assert!(admin.can_write());
        assert!(admin.is_admin());
    }
}
