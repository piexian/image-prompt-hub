//! 发信：统一 trait，SMTP 与 Cloudflare 两个实现，测试用内存假发信器。

pub mod cloudflare;
pub mod smtp;

use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::EmailProvider;
use crate::error::ApiError;

/// 封装一封已发出的邮件，供测试断言。
#[derive(Debug, Clone)]
pub struct SentMail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), String>;
}

/// 未配置发信时的占位实现，调用即失败。
pub struct DisabledMailer;

#[async_trait]
impl Mailer for DisabledMailer {
    async fn send(&self, _to: &str, _subject: &str, _body: &str) -> Result<(), String> {
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
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("测试模拟的发送失败".to_string());
        }
        self.sent.lock().await.push(SentMail {
            to: to.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
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

/// 验证邮件正文。purpose 决定措辞是申请还是重置。
pub fn verification_email_body(purpose: &str, link: &str) -> String {
    let action = if purpose == "reset" {
        "重置 API 密钥。确认后将生成新密钥，并立即作废你当前有效的密钥。"
    } else {
        "申请 API 密钥。确认后新密钥将发送到这个邮箱。"
    };
    format!(
        "你（或他人）正在为这个邮箱{action}\n\n\
         请在 30 分钟内打开下面的链接并点击“确认”按钮完成操作：\n\
         {link}\n\n\
         打开链接本身不会生效，必须在页面上点击“确认”。\n\
         如果不是你本人的操作，忽略这封邮件即可，不会有任何影响。\n"
    )
}

/// 密钥邮件正文。吊销走邮件里的链接确认页，不再引导用户调接口。
pub fn api_key_email_body(key: &str, revoke_link: &str) -> String {
    format!(
        "你的 API 密钥如下，只显示这一次，请妥善保存：\n\n\
         {key}\n\n\
         在 AstrBot 图片生成插件的提示词广场“在线”页里选择“填写密钥”并粘贴上面的密钥即可使用。\n\n\
         吊销方式：打开下面的链接，在页面上点击“确认吊销”即可（打开链接本身不会吊销）：\n\
         {revoke_link}\n\
         也可以用同一邮箱重新申请，重置会作废旧密钥。\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_mailer_records_and_fails() {
        let mailer = FakeMailer::new();
        mailer.send("a@b.com", "主题", "正文").await.unwrap();
        assert_eq!(mailer.mails().await.len(), 1);
        mailer.set_fail(true);
        assert!(mailer.send("a@b.com", "主题", "正文").await.is_err());
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

    #[test]
    fn verification_body_wording() {
        let reset = verification_email_body("reset", "https://x.example/v1/keys/verify?token=t");
        assert!(reset.contains("作废"));
        let issue = verification_email_body("issue", "https://x.example/v1/keys/verify?token=t");
        assert!(!issue.contains("作废你当前"));
        assert!(issue.contains("申请"));
        assert!(issue.contains("https://x.example/v1/keys/verify?token=t"));
    }

    #[test]
    fn api_key_body_contents() {
        let link = "https://hub.example.com/v1/keys/revoke?token=x";
        let body = api_key_email_body("iph_abc", link);
        assert!(body.contains("iph_abc"));
        assert!(body.contains(link), "正文必须包含完整吊销链接");
        assert!(!body.contains("DELETE /v1/key"), "不再引导用户调接口");
        assert!(body.contains("在线"));
        assert!(body.contains("确认吊销"));
        assert!(body.contains("重置会作废旧密钥"));
    }
}
