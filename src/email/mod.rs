//! 发信：统一 trait，SMTP 与 Cloudflare 两个实现，测试用内存假发信器。

pub mod cloudflare;
pub mod smtp;
pub mod templates;

use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::EmailProvider;
use crate::error::ApiError;

/// 封装一封已发出的邮件，供测试断言。`body` 是纯文本部分，`html` 是 HTML 部分。
#[derive(Debug, Clone)]
pub struct SentMail {
    pub to: String,
    pub subject: String,
    pub body: String,
    pub html: String,
}

#[async_trait]
pub trait Mailer: Send + Sync {
    /// `text` 是纯文本回退，`html` 是 HTML 正文，客户端按能力选择显示哪个。
    async fn send(&self, to: &str, subject: &str, text: &str, html: &str) -> Result<(), String>;
}

/// 未配置发信时的占位实现，调用即失败。
pub struct DisabledMailer;

#[async_trait]
impl Mailer for DisabledMailer {
    async fn send(
        &self,
        _to: &str,
        _subject: &str,
        _text: &str,
        _html: &str,
    ) -> Result<(), String> {
        Err("邮件服务未启用".to_string())
    }
}

/// 测试与本地调试用：把邮件记在内存里，可切换为发送失败。
#[derive(Clone)]
pub struct FakeMailer {
    pub sent: std::sync::Arc<AsyncMutex<Vec<SentMail>>>,
    pub fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl FakeMailer {
    pub fn new() -> Self {
        Self {
            sent: std::sync::Arc::new(AsyncMutex::new(Vec::new())),
            fail: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn set_fail(&self, fail: bool) {
        self.fail.store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    pub async fn mails(&self) -> Vec<SentMail> {
        self.sent.lock().await.clone()
    }
}

impl Default for FakeMailer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Mailer for FakeMailer {
    async fn send(&self, to: &str, subject: &str, text: &str, html: &str) -> Result<(), String> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("测试模拟的发送失败".to_string());
        }
        self.sent.lock().await.push(SentMail {
            to: to.to_string(),
            subject: subject.to_string(),
            body: text.to_string(),
            html: html.to_string(),
        });
        Ok(())
    }
}

/// 把文本里形似邮箱地址的片段替换成 `***`。发信失败的错误信息可能带着服务器回显的
/// 收件地址，写日志前必须先脱敏。
pub fn redact_emails(text: &str) -> String {
    let is_local = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-');
    let is_domain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-');
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '@' {
            let local_len = out.chars().rev().take_while(|&c| is_local(c)).count();
            let domain_end = chars[index + 1..]
                .iter()
                .position(|&c| !is_domain(c))
                .map_or(chars.len(), |offset| index + 1 + offset);
            if local_len > 0 && domain_end > index + 1 {
                for _ in 0..local_len {
                    out.pop();
                }
                out.push_str("***");
                index = domain_end;
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

pub fn build_mailer(
    provider: EmailProvider,
    config: &crate::config::Config,
) -> Result<std::sync::Arc<dyn Mailer>, String> {
    match provider {
        EmailProvider::Disabled => Ok(std::sync::Arc::new(DisabledMailer)),
        EmailProvider::Smtp => Ok(std::sync::Arc::new(smtp::SmtpMailer::new(
            &config.smtp.host,
            config.smtp.port,
            &config.smtp.username,
            &config.smtp.password,
            &config.smtp.from,
            &config.smtp.from_name,
            config.smtp.encryption,
            config.smtp.auth_method,
            config.smtp.validate_certs,
        )?)),
        EmailProvider::Cloudflare => {
            if config.cloudflare.account_id.is_empty()
                || config.cloudflare.api_token.is_empty()
                || config.cloudflare.from.is_empty()
            {
                return Err("EMAIL_PROVIDER=cloudflare 需要配置 CLOUDFLARE_EMAIL_ACCOUNT_ID、CLOUDFLARE_EMAIL_API_TOKEN 与 CLOUDFLARE_EMAIL_FROM".to_string());
            }
            Ok(std::sync::Arc::new(cloudflare::CloudflareMailer::new(
                &config.cloudflare.account_id,
                &config.cloudflare.api_token,
                &config.cloudflare.from,
                &config.cloudflare.from_name,
            )))
        }
    }
}

/// 全站每日发信上限检查；0 表示不限。
pub async fn check_email_daily_limit(pool: &PgPool, limit: u32) -> Result<(), ApiError> {
    if limit == 0 {
        return Ok(());
    }
    let day = Utc::now().date_naive();
    let count: i64 = sqlx::query_scalar("SELECT count FROM email_daily_counter WHERE day = $1")
        .bind(day)
        .fetch_optional(pool)
        .await
        .map_err(ApiError::from)?
        .unwrap_or(0);
    if count >= i64::from(limit) {
        return Err(ApiError::rate_limited(seconds_until_tomorrow()));
    }
    Ok(())
}

/// 发送成功后计数加一；0 表示不计数。
pub async fn increment_email_daily_count(pool: &PgPool, limit: u32) -> Result<(), ApiError> {
    if limit == 0 {
        return Ok(());
    }
    let day = Utc::now().date_naive();
    sqlx::query(
        "INSERT INTO email_daily_counter (day, count) VALUES ($1, 1)
         ON CONFLICT (day) DO UPDATE SET count = email_daily_counter.count + 1",
    )
    .bind(day)
    .execute(pool)
    .await
    .map_err(ApiError::from)?;
    Ok(())
}

fn seconds_until_tomorrow() -> u64 {
    let now = Utc::now();
    let tomorrow = (now + chrono::Duration::days(1))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("零点时间有效");
    let tomorrow = chrono::DateTime::<Utc>::from_naive_utc_and_offset(tomorrow, Utc);
    (tomorrow - now).num_seconds().max(1) as u64
}

pub const VERIFICATION_SUBJECT: &str = "验证你的邮箱 - image-prompt-hub 密钥申请";
pub const API_KEY_SUBJECT: &str = "你的 image-prompt-hub API 密钥";

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_mailer_records_and_fails() {
        let mailer = FakeMailer::new();
        mailer
            .send("a@b.com", "主题", "正文", "<p>正文</p>")
            .await
            .unwrap();
        let mails = mailer.mails().await;
        assert_eq!(mails.len(), 1);
        assert_eq!(mails[0].body, "正文");
        assert_eq!(mails[0].html, "<p>正文</p>");
        mailer.set_fail(true);
        assert!(mailer
            .send("a@b.com", "主题", "正文", "<p>x</p>")
            .await
            .is_err());
        assert_eq!(mailer.mails().await.len(), 1);
    }

    #[test]
    fn redact_emails_masks_addresses_only() {
        assert_eq!(
            redact_emails("550 5.1.1 <foo.bar+tag@qq.com>: Recipient address rejected"),
            "550 5.1.1 <***>: Recipient address rejected"
        );
        assert_eq!(
            redact_emails("a@b.com, 然后 c_d@sub.pku.edu.cn。"),
            "***, 然后 ***。"
        );
        assert_eq!(
            redact_emails("没有邮箱的文本 @ 单独的 at 号"),
            "没有邮箱的文本 @ 单独的 at 号"
        );
        assert_eq!(redact_emails("name@"), "name@");
        assert_eq!(redact_emails("@domain.com"), "@domain.com");
        assert_eq!(redact_emails(""), "");
    }
}
