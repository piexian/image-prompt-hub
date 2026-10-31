//! Cloudflare Email Sending 发信实现，请求与错误处理对齐插件市场。

use async_trait::async_trait;
use serde_json::json;
use std::time::Duration;

use crate::email::Mailer;

const DEFAULT_ENDPOINT_BASE: &str = "https://api.cloudflare.com/client/v4";
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

pub struct CloudflareMailer {
    client: reqwest::Client,
    endpoint_base: String,
    account_id: String,
    api_token: String,
    from: String,
    from_name: String,
}

impl CloudflareMailer {
    pub fn new(account_id: &str, api_token: &str, from: &str, from_name: &str) -> Self {
        Self::with_endpoint_base(
            DEFAULT_ENDPOINT_BASE,
            account_id,
            api_token,
            from,
            from_name,
        )
    }

    /// 测试注入本地假服务器地址。
    pub fn with_endpoint_base(
        endpoint_base: &str,
        account_id: &str,
        api_token: &str,
        from: &str,
        from_name: &str,
    ) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(SEND_TIMEOUT)
                .build()
                .expect("reqwest 客户端构建不会失败"),
            endpoint_base: endpoint_base.trim_end_matches('/').to_string(),
            account_id: account_id.to_string(),
            api_token: api_token.to_string(),
            from: from.to_string(),
            from_name: from_name.to_string(),
        }
    }

    fn endpoint(&self) -> String {
        format!(
            "{}/accounts/{}/email/sending/send",
            self.endpoint_base,
            url_escape(&self.account_id)
        )
    }

    /// 与插件市场一致的请求体；html 由调用方传入，不再从纯文本转义生成。
    pub fn request_body(
        &self,
        to: &str,
        subject: &str,
        text: &str,
        html: &str,
    ) -> serde_json::Value {
        json!({
            "to": to,
            "from": {
                "email": self.from,
                "name": sender_name(&self.from_name),
            },
            "subject": truncate_chars(subject, 998),
            "text": text,
            "html": html,
        })
    }
}

/// 查询串里的保留字符按插件市场同样做百分号编码（安全字符集保持一致）。
fn url_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn sender_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        "image-prompt-hub".to_string()
    } else {
        trimmed.to_string()
    }
}

fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        text.chars().take(max).collect()
    }
}

/// 按状态码与响应体判断成败，错误信息不含凭据。
fn classify_response(status: reqwest::StatusCode, body: &[u8]) -> Result<(), String> {
    if status.as_u16() == 429 {
        return Err("Cloudflare 邮件服务被限流".to_string());
    }
    if status.as_u16() == 401 || status.as_u16() == 403 {
        return Err("Cloudflare 邮件服务认证失败".to_string());
    }
    if status.as_u16() >= 500 {
        return Err(format!("Cloudflare 邮件服务错误：HTTP {}", status.as_u16()));
    }
    let data: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    if status.as_u16() >= 400
        || !data
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    {
        let messages: Vec<String> = data
            .get("errors")
            .and_then(|v| v.as_array())
            .map(|errors| {
                errors
                    .iter()
                    .filter_map(|item| {
                        Some(format!(
                            "[{}] {}",
                            item.get("code")?.as_u64().unwrap_or(0),
                            item.get("message")?.as_str().unwrap_or("")
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if messages.is_empty() {
            return Err(format!(
                "Cloudflare 邮件 API 错误：HTTP {}",
                status.as_u16()
            ));
        }
        return Err(format!("Cloudflare 邮件 API 错误：{}", messages.join("; ")));
    }
    let permanent_bounces = data
        .get("result")
        .and_then(|v| v.get("permanent_bounces"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if !permanent_bounces.is_empty() {
        // 只报告数量：退信列表里是收件人邮箱，不能进入错误信息和日志
        return Err(format!(
            "Cloudflare 邮件永久退信（{} 个收件地址）",
            permanent_bounces.len()
        ));
    }
    Ok(())
}

#[async_trait]
impl Mailer for CloudflareMailer {
    async fn send(&self, to: &str, subject: &str, text: &str, html: &str) -> Result<(), String> {
        if self.account_id.is_empty() {
            return Err("Cloudflare account ID 未配置".to_string());
        }
        if self.api_token.is_empty() {
            return Err("Cloudflare API token 未配置".to_string());
        }
        if self.from.is_empty() {
            return Err("Cloudflare 发件地址未配置".to_string());
        }
        let response = self
            .client
            .post(self.endpoint())
            .bearer_auth(&self.api_token)
            .json(&self.request_body(to, subject, text, html))
            .send()
            .await
            .map_err(|e| format!("Cloudflare 请求失败：{e}"))?;
        let status = response.status();
        let body_bytes = response
            .bytes()
            .await
            .map_err(|e| format!("Cloudflare 响应读取失败：{e}"))?;
        classify_response(status, &body_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_body_shape() {
        let mailer = CloudflareMailer::with_endpoint_base(
            "http://127.0.0.1:1",
            "acc id+1",
            "token",
            "noreply@example.com",
            "模板服务",
        );
        let body = mailer.request_body("to@example.com", "主题", "纯文本", "<p>HTML 正文</p>");
        assert_eq!(body["to"], "to@example.com");
        assert_eq!(body["from"]["email"], "noreply@example.com");
        assert_eq!(body["from"]["name"], "模板服务");
        assert_eq!(body["subject"], "主题");
        assert_eq!(body["text"], "纯文本");
        // html 由调用方传入，原样发送
        assert_eq!(body["html"], "<p>HTML 正文</p>");
        assert!(mailer
            .endpoint()
            .ends_with("/accounts/acc%20id%2B1/email/sending/send"));
        // 默认发件名兜底
        let default_name =
            CloudflareMailer::with_endpoint_base("http://x", "a", "t", "f@x.com", "  ");
        assert_eq!(
            default_name.request_body("t@x.com", "s", "b", "h")["from"]["name"],
            "image-prompt-hub"
        );
    }

    #[test]
    fn subject_truncated_to_998_chars() {
        let mailer = CloudflareMailer::with_endpoint_base("http://x", "a", "t", "f@x.com", "n");
        let long_subject = "字".repeat(1200);
        let body = mailer.request_body("t@x.com", &long_subject, "b", "h");
        assert_eq!(body["subject"].as_str().unwrap().chars().count(), 998);
    }

    #[test]
    fn classify_response_errors() {
        let ok = serde_json::json!({"success": true, "result": {}}).to_string();
        assert!(classify_response(reqwest::StatusCode::OK, ok.as_bytes()).is_ok());
        let bounced =
            serde_json::json!({"success": true, "result": {"permanent_bounces": ["a@b.com"]}})
                .to_string();
        assert!(
            classify_response(reqwest::StatusCode::OK, bounced.as_bytes())
                .unwrap_err()
                .contains("永久退信")
        );
        let api_err =
            serde_json::json!({"success": false, "errors": [{"code": 1003, "message": "bad"}]})
                .to_string();
        assert_eq!(
            classify_response(reqwest::StatusCode::OK, api_err.as_bytes()).unwrap_err(),
            "Cloudflare 邮件 API 错误：[1003] bad"
        );
        assert_eq!(
            classify_response(reqwest::StatusCode::UNAUTHORIZED, b"").unwrap_err(),
            "Cloudflare 邮件服务认证失败"
        );
        assert_eq!(
            classify_response(reqwest::StatusCode::TOO_MANY_REQUESTS, b"").unwrap_err(),
            "Cloudflare 邮件服务被限流"
        );
        assert!(classify_response(reqwest::StatusCode::BAD_GATEWAY, b"")
            .unwrap_err()
            .contains("HTTP 502"));
        assert!(classify_response(reqwest::StatusCode::OK, b"not json")
            .unwrap_err()
            .contains("HTTP 200"));
    }
}
