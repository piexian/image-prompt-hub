//! 环境变量配置。所有密钥类字段的 Debug 输出一律打码。

use std::net::SocketAddr;
use std::path::PathBuf;

use crate::crypto;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailProvider {
    Disabled,
    Smtp,
    Cloudflare,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpEncryption {
    Auto,
    None,
    StartTls,
    SslTls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpAuthMethod {
    Auto,
    Login,
    Plain,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Pretty,
    Json,
}

/// 邮箱后缀白名单规则：精确匹配或 `*.edu.cn` 形式的后缀匹配。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainRule {
    Exact(String),
    /// 域名本身及其所有子域名。
    Suffix(String),
}

impl DomainRule {
    pub fn parse(rule: &str) -> Option<Self> {
        let rule = rule.trim().to_ascii_lowercase();
        if rule.is_empty() {
            return None;
        }
        if let Some(suffix) = rule.strip_prefix("*.") {
            if suffix.is_empty() {
                return None;
            }
            Some(DomainRule::Suffix(suffix.to_string()))
        } else {
            Some(DomainRule::Exact(rule))
        }
    }

    pub fn matches(&self, domain: &str) -> bool {
        match self {
            DomainRule::Exact(exact) => domain == exact,
            DomainRule::Suffix(suffix) => {
                domain == suffix || domain.ends_with(&format!(".{suffix}"))
            }
        }
    }
}

#[derive(Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub from_name: String,
    pub encryption: SmtpEncryption,
    pub auth_method: SmtpAuthMethod,
    pub validate_certs: bool,
}

#[derive(Clone)]
pub struct CloudflareEmailConfig {
    pub account_id: String,
    pub api_token: String,
    pub from: String,
    pub from_name: String,
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    pub anon_read_per_min: u32,
    pub keyed_read_per_min: u32,
    pub write_per_min: u32,
    pub key_request_per_hour: u32,
    pub key_verify_per_hour: u32,
    pub report_per_hour: u32,
    pub auth_failure_per_min: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            anon_read_per_min: 60,
            keyed_read_per_min: 600,
            write_per_min: 60,
            key_request_per_hour: 5,
            key_verify_per_hour: 20,
            report_per_hour: 10,
            auth_failure_per_min: 30,
        }
    }
}

/// 必填密钥与连接串，Debug 不暴露内容。
#[derive(Clone)]
pub struct Secrets {
    pub database_url: String,
    pub key_pepper: String,
    pub email_hash_secret: String,
    pub ip_hash_secret: String,
    pub email_enc_key: [u8; 32],
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("database_url", &"***")
            .field("key_pepper", &"***")
            .field("email_hash_secret", &"***")
            .field("ip_hash_secret", &"***")
            .field("email_enc_key", &"***")
            .finish()
    }
}

#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub data_dir: PathBuf,
    pub public_base_url: String,
    pub trust_cf_connecting_ip: bool,
    pub secrets: Secrets,
    pub email_domain_allowlist: Vec<DomainRule>,
    pub email_provider: EmailProvider,
    pub smtp: SmtpConfig,
    pub cloudflare: CloudflareEmailConfig,
    pub email_daily_limit: u32,
    pub email_cooldown_secs: u64,
    pub email_per_day_limit: u32,
    pub account_create_per_hour: u32,
    pub account_template_limit: u32,
    pub catalog_debounce_secs: u64,
    pub rate_limits: RateLimitConfig,
    pub log_format: LogFormat,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("data_dir", &self.data_dir)
            .field("public_base_url", &self.public_base_url)
            .field("trust_cf_connecting_ip", &self.trust_cf_connecting_ip)
            .field("secrets", &self.secrets)
            .field("email_domain_allowlist", &self.email_domain_allowlist)
            .field("email_provider", &self.email_provider)
            .field("smtp", &"SmtpConfig(***)")
            .field("cloudflare", &"CloudflareEmailConfig(***)")
            .field("email_daily_limit", &self.email_daily_limit)
            .field("email_cooldown_secs", &self.email_cooldown_secs)
            .field("email_per_day_limit", &self.email_per_day_limit)
            .field("account_create_per_hour", &self.account_create_per_hour)
            .field("account_template_limit", &self.account_template_limit)
            .field("catalog_debounce_secs", &self.catalog_debounce_secs)
            .field("rate_limits", &self.rate_limits)
            .field("log_format", &self.log_format)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8787".parse().unwrap(),
            data_dir: PathBuf::from("./data"),
            public_base_url: String::new(),
            trust_cf_connecting_ip: true,
            secrets: Secrets {
                database_url: String::new(),
                key_pepper: String::new(),
                email_hash_secret: String::new(),
                ip_hash_secret: String::new(),
                email_enc_key: [0u8; 32],
            },
            email_domain_allowlist: "qq.com,foxmail.com,163.com,gmail.com,*.edu.cn"
                .split(',')
                .filter_map(DomainRule::parse)
                .collect(),
            email_provider: EmailProvider::Disabled,
            smtp: SmtpConfig {
                host: String::new(),
                port: 587,
                username: String::new(),
                password: String::new(),
                from: String::new(),
                from_name: "image-prompt-hub".to_string(),
                encryption: SmtpEncryption::Auto,
                auth_method: SmtpAuthMethod::Auto,
                validate_certs: true,
            },
            cloudflare: CloudflareEmailConfig {
                account_id: String::new(),
                api_token: String::new(),
                from: String::new(),
                from_name: "image-prompt-hub".to_string(),
            },
            email_daily_limit: 0,
            email_cooldown_secs: 600,
            email_per_day_limit: 5,
            account_create_per_hour: 100,
            account_template_limit: 1000,
            catalog_debounce_secs: 60,
            rate_limits: RateLimitConfig::default(),
            log_format: LogFormat::Pretty,
        }
    }
}

/// 环境变量读取抽象：生产用进程环境，测试注入固定映射。
type Lookup<'a> = &'a dyn Fn(&str) -> Option<String>;

fn env_str(lookup: Lookup<'_>, key: &str) -> Option<String> {
    lookup(key)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// 布尔解析：未设置为默认值，无法识别的取值报错（避免拼写错误被当成 false）。
fn env_bool(lookup: Lookup<'_>, key: &str, default: bool) -> Result<bool, String> {
    match env_str(lookup, key).map(|v| v.to_ascii_lowercase()) {
        Some(v) if matches!(v.as_str(), "true" | "1" | "yes" | "on") => Ok(true),
        Some(v) if matches!(v.as_str(), "false" | "0" | "no" | "off") => Ok(false),
        Some(v) => Err(format!("{key} 的值无效：{v}（应为 true/false）")),
        None => Ok(default),
    }
}

fn env_parse<T>(lookup: Lookup<'_>, key: &str, default: T, min: T) -> Result<T, String>
where
    T: std::str::FromStr + std::fmt::Display + PartialOrd + Copy,
{
    match env_str(lookup, key) {
        Some(v) => {
            let parsed = v.parse::<T>().map_err(|_| format!("{key} 的值无效：{v}"))?;
            if parsed >= min {
                Ok(parsed)
            } else {
                Err(format!("{key} 的取值超出允许范围：{parsed}"))
            }
        }
        None => Ok(default),
    }
}

/// 与插件市场一致的 SMTP_ENCRYPTION 归一化，未知值回落到 auto。
pub fn normalize_smtp_encryption(value: &str) -> SmtpEncryption {
    let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
    match normalized.as_str() {
        "none" | "plain" => SmtpEncryption::None,
        "starttls" | "start_tls" => SmtpEncryption::StartTls,
        "ssl" | "tls" | "ssl_tls" => SmtpEncryption::SslTls,
        _ => SmtpEncryption::Auto,
    }
}

/// 与插件市场一致的 SMTP_AUTH_METHOD 归一化，未知值回落到 auto。
pub fn normalize_smtp_auth_method(value: &str) -> SmtpAuthMethod {
    let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
    match normalized.as_str() {
        "login" => SmtpAuthMethod::Login,
        "plain" => SmtpAuthMethod::Plain,
        "none" => SmtpAuthMethod::None,
        _ => SmtpAuthMethod::Auto,
    }
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(&|key| std::env::var(key).ok())
    }

    /// 从任意键值来源加载配置；`from_env` 与单元测试共用这一条解析路径。
    pub fn from_lookup(lookup: Lookup<'_>) -> Result<Self, String> {
        let mut config = Config::default();

        if let Some(value) = env_str(lookup, "BIND_ADDR") {
            config.bind_addr = value
                .parse()
                .map_err(|_| format!("BIND_ADDR 不是有效的监听地址：{value}"))?;
        }
        if let Some(value) = env_str(lookup, "DATA_DIR") {
            config.data_dir = PathBuf::from(value);
        }

        let mut missing = Vec::new();
        let mut required = |key: &'static str| {
            env_str(lookup, key).unwrap_or_else(|| {
                missing.push(key);
                String::new()
            })
        };
        let database_url = required("DATABASE_URL");
        let public_base_url = required("PUBLIC_BASE_URL");
        let key_pepper = required("KEY_PEPPER");
        let email_hash_secret = required("EMAIL_HASH_SECRET");
        let ip_hash_secret = required("IP_HASH_SECRET");
        let email_enc_key_b64 = required("EMAIL_ENC_KEY");
        if !missing.is_empty() {
            return Err(format!("缺少必填环境变量：{}", missing.join("、")));
        }
        let email_enc_key = crypto::decode_base64_standard(&email_enc_key_b64)
            .map_err(|_| "EMAIL_ENC_KEY 不是有效的 base64".to_string())
            .and_then(|bytes| {
                let array: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| "EMAIL_ENC_KEY 解码后必须是 32 字节".to_string())?;
                Ok(array)
            })?;

        validate_secrets(
            &key_pepper,
            &email_hash_secret,
            &ip_hash_secret,
            &email_enc_key,
        )?;
        config.secrets = Secrets {
            database_url,
            key_pepper,
            email_hash_secret,
            ip_hash_secret,
            email_enc_key,
        };
        config.public_base_url = validate_base_url(&public_base_url)?;
        config.trust_cf_connecting_ip = env_bool(lookup, "TRUST_CF_CONNECTING_IP", true)?;

        if let Some(value) = env_str(lookup, "EMAIL_DOMAIN_ALLOWLIST") {
            let rules: Vec<DomainRule> = value.split(',').filter_map(DomainRule::parse).collect();
            if !rules.is_empty() {
                config.email_domain_allowlist = rules;
            }
        }
        if let Some(value) = env_str(lookup, "EMAIL_PROVIDER") {
            config.email_provider = match value.to_ascii_lowercase().as_str() {
                "disabled" => EmailProvider::Disabled,
                "smtp" => EmailProvider::Smtp,
                "cloudflare" => EmailProvider::Cloudflare,
                other => return Err(format!("EMAIL_PROVIDER 的取值无效：{other}")),
            };
        }

        config.smtp = SmtpConfig {
            host: env_str(lookup, "SMTP_HOST").unwrap_or_default(),
            port: env_parse(lookup, "SMTP_PORT", 587u16, 1u16)?,
            username: env_str(lookup, "SMTP_USERNAME").unwrap_or_default(),
            password: env_str(lookup, "SMTP_PASSWORD").unwrap_or_default(),
            from: env_str(lookup, "SMTP_FROM").unwrap_or_default(),
            from_name: env_str(lookup, "SMTP_FROM_NAME")
                .unwrap_or_else(|| "image-prompt-hub".to_string()),
            encryption: normalize_smtp_encryption(
                &env_str(lookup, "SMTP_ENCRYPTION").unwrap_or_default(),
            ),
            auth_method: normalize_smtp_auth_method(
                &env_str(lookup, "SMTP_AUTH_METHOD").unwrap_or_default(),
            ),
            validate_certs: env_bool(lookup, "SMTP_VALIDATE_CERTS", true)?,
        };
        config.cloudflare = CloudflareEmailConfig {
            account_id: env_str(lookup, "CLOUDFLARE_EMAIL_ACCOUNT_ID").unwrap_or_default(),
            api_token: env_str(lookup, "CLOUDFLARE_EMAIL_API_TOKEN").unwrap_or_default(),
            from: env_str(lookup, "CLOUDFLARE_EMAIL_FROM").unwrap_or_default(),
            from_name: env_str(lookup, "CLOUDFLARE_EMAIL_FROM_NAME")
                .unwrap_or_else(|| "image-prompt-hub".to_string()),
        };

        config.email_daily_limit = env_parse(lookup, "EMAIL_DAILY_LIMIT", 0u32, 0u32)?;
        config.email_cooldown_secs = env_parse(lookup, "EMAIL_COOLDOWN_SECS", 600u64, 1u64)?;
        config.email_per_day_limit = env_parse(lookup, "EMAIL_PER_DAY_LIMIT", 5u32, 1u32)?;
        config.account_create_per_hour =
            env_parse(lookup, "ACCOUNT_CREATE_PER_HOUR", 100u32, 1u32)?;
        config.account_template_limit = env_parse(lookup, "ACCOUNT_TEMPLATE_LIMIT", 1000u32, 1u32)?;
        config.catalog_debounce_secs = env_parse(lookup, "CATALOG_DEBOUNCE_SECS", 60u64, 0u64)?;
        let defaults = RateLimitConfig::default();
        config.rate_limits = RateLimitConfig {
            anon_read_per_min: env_parse(
                lookup,
                "RATE_ANON_READ_PER_MIN",
                defaults.anon_read_per_min,
                1,
            )?,
            keyed_read_per_min: env_parse(
                lookup,
                "RATE_KEYED_READ_PER_MIN",
                defaults.keyed_read_per_min,
                1,
            )?,
            write_per_min: env_parse(lookup, "RATE_WRITE_PER_MIN", defaults.write_per_min, 1)?,
            key_request_per_hour: env_parse(
                lookup,
                "RATE_KEY_REQUEST_PER_HOUR",
                defaults.key_request_per_hour,
                1,
            )?,
            key_verify_per_hour: env_parse(
                lookup,
                "RATE_KEY_VERIFY_PER_HOUR",
                defaults.key_verify_per_hour,
                1,
            )?,
            report_per_hour: env_parse(
                lookup,
                "RATE_REPORT_PER_HOUR",
                defaults.report_per_hour,
                1,
            )?,
            auth_failure_per_min: env_parse(
                lookup,
                "RATE_AUTH_FAILURE_PER_MIN",
                defaults.auth_failure_per_min,
                1,
            )?,
        };
        if let Some(value) = env_str(lookup, "LOG_FORMAT") {
            config.log_format = match value.to_ascii_lowercase().as_str() {
                "pretty" => LogFormat::Pretty,
                "json" => LogFormat::Json,
                other => return Err(format!("LOG_FORMAT 的取值无效：{other}")),
            };
        }

        Ok(config)
    }

    /// 监听地址不是回环而又信任 `CF-Connecting-IP` 时，直连的请求可以伪造该头。
    pub fn trusts_spoofable_ip_header(&self) -> bool {
        self.trust_cf_connecting_ip && !self.bind_addr.ip().is_loopback()
    }

    pub fn email_hmac(&self, email: &str) -> String {
        crypto::hmac_hex(self.secrets.email_hash_secret.as_bytes(), email.as_bytes())
    }

    /// 账号身份哈希：以规范化身份（gmail 去点与 +后缀、其他域名去 +后缀）为输入，
    /// 用于"一个邮箱一把密钥"、限频、封禁与模板归属。
    pub fn account_hmac(&self, email: &str) -> String {
        self.email_hmac(&crate::validate::email_identity(email))
    }

    /// 无状态吊销令牌：`"{key_id}.{mac}"`，mac 以 "revoke-v1:{key_id}" 为消息、
    /// KEY_PEPPER 为密钥。不落库，泄露 KEY_PEPPER 前不可伪造。
    pub fn revoke_token(&self, key_id: uuid::Uuid) -> String {
        let mac = crypto::hmac_hex(
            self.secrets.key_pepper.as_bytes(),
            format!("revoke-v1:{key_id}").as_bytes(),
        );
        format!("{key_id}.{mac}")
    }

    /// 校验吊销令牌。解析失败、长度不对、MAC 不符一律返回 None，不区分原因。
    pub fn verify_revoke_token(&self, token: &str) -> Option<uuid::Uuid> {
        let (id_part, mac) = token.split_once('.')?;
        let key_id = uuid::Uuid::parse_str(id_part).ok()?;
        let expected = crypto::hmac_hex(
            self.secrets.key_pepper.as_bytes(),
            format!("revoke-v1:{key_id}").as_bytes(),
        );
        if crypto::constant_time_eq(mac.as_bytes(), expected.as_bytes()) {
            Some(key_id)
        } else {
            None
        }
    }

    pub fn ip_hash(&self, ip: &str) -> String {
        crypto::hmac_hex(self.secrets.ip_hash_secret.as_bytes(), ip.as_bytes())
    }

    pub fn key_hash(&self, key: &str) -> String {
        crypto::hmac_hex(self.secrets.key_pepper.as_bytes(), key.as_bytes())
    }
}

/// 三个 HMAC 密钥的强度与互异性校验，并拒绝占位值与全零加密密钥。
fn validate_secrets(
    key_pepper: &str,
    email_hash_secret: &str,
    ip_hash_secret: &str,
    email_enc_key: &[u8; 32],
) -> Result<(), String> {
    for (name, value) in [
        ("KEY_PEPPER", key_pepper),
        ("EMAIL_HASH_SECRET", email_hash_secret),
        ("IP_HASH_SECRET", ip_hash_secret),
    ] {
        if value.chars().count() < 32 {
            return Err(format!("{name} 至少需要 32 个字符"));
        }
        if value.contains("change-me") {
            return Err(format!("{name} 不能包含 change-me，请换成随机值"));
        }
    }
    if key_pepper == email_hash_secret
        || key_pepper == ip_hash_secret
        || email_hash_secret == ip_hash_secret
    {
        return Err("KEY_PEPPER、EMAIL_HASH_SECRET、IP_HASH_SECRET 必须互不相同".to_string());
    }
    if email_enc_key.iter().all(|&byte| byte == 0) {
        return Err("EMAIL_ENC_KEY 不能是全零字节".to_string());
    }
    Ok(())
}

/// 对外地址必须是 https，仅本机主机名允许 http。
fn validate_base_url(url: &str) -> Result<String, String> {
    let url = url.trim_end_matches('/');
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("PUBLIC_BASE_URL 必须以 http:// 或 https:// 开头：{url}"))?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // 去掉 userinfo，避免 `http://localhost@evil.example` 这类写法绕过主机判断
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    // IPv6 字面量带方括号，端口在其后
    let host = match host_port
        .strip_prefix('[')
        .and_then(|_| host_port.find(']'))
    {
        Some(close) => &host_port[..=close],
        None => host_port.split(':').next().unwrap_or(host_port),
    };
    if host.is_empty() {
        return Err(format!("PUBLIC_BASE_URL 缺少主机名：{url}"));
    }
    let normalized = format!("{scheme}://{rest}");
    match scheme.as_str() {
        "https" => Ok(normalized),
        "http"
            if matches!(
                host.to_ascii_lowercase().as_str(),
                "localhost" | "127.0.0.1" | "[::1]"
            ) =>
        {
            Ok(normalized)
        }
        "http" => Err(format!(
            "PUBLIC_BASE_URL 必须是 https（仅 localhost/127.0.0.1/[::1] 允许 http）：{url}"
        )),
        other => Err(format!("PUBLIC_BASE_URL 的协议无效：{other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_rule_matching() {
        let edu = DomainRule::parse("*.edu.cn").unwrap();
        assert!(edu.matches("edu.cn"));
        assert!(edu.matches("tsinghua.edu.cn"));
        assert!(edu.matches("pku.edu.cn"));
        assert!(!edu.matches("fakeedu.cn"));
        assert!(!edu.matches("edu.cn.evil.com"));

        let qq = DomainRule::parse("qq.com").unwrap();
        assert!(qq.matches("qq.com"));
        assert!(!qq.matches("evilqq.com"));
        assert!(!qq.matches("sub.qq.com"));

        assert!(DomainRule::parse(" *.QQ.com ").unwrap().matches("qq.com"));
        assert!(DomainRule::parse("").is_none());
        assert!(DomainRule::parse("*.").is_none());
    }

    #[test]
    fn secrets_validation_rules() {
        let long = "a".repeat(32);
        let short = "a".repeat(31);
        let key = [1u8; 32];
        assert!(validate_secrets(&long, &"b".repeat(32), &"c".repeat(32), &key).is_ok());
        assert!(validate_secrets(&short, &"b".repeat(32), &"c".repeat(32), &key).is_err());
        assert!(validate_secrets(&long, &"b".repeat(32), &"c".repeat(32), &[0u8; 32]).is_err());
        assert!(validate_secrets(
            "change-me-random-value-1234567890ab",
            &"b".repeat(32),
            &"c".repeat(32),
            &key
        )
        .is_err());
        assert!(validate_secrets(&long, &long, &"c".repeat(32), &key).is_err());
        assert!(validate_secrets(&long, &"b".repeat(32), &long, &key).is_err());
    }

    #[test]
    fn base_url_rules() {
        assert!(validate_base_url("https://hub.example.com").is_ok());
        assert_eq!(
            validate_base_url("https://hub.example.com/path/").unwrap(),
            "https://hub.example.com/path"
        );
        assert_eq!(
            validate_base_url("HTTPS://Hub.Example.com").unwrap(),
            "https://Hub.Example.com"
        );
        assert!(validate_base_url("http://localhost:8787").is_ok());
        assert!(validate_base_url("http://LOCALHOST:8787").is_ok());
        assert!(validate_base_url("http://127.0.0.1:8787").is_ok());
        assert!(validate_base_url("http://[::1]:8787").is_ok());
        assert!(validate_base_url("http://hub.example.com").is_err());
        assert!(validate_base_url("hub.example.com").is_err());
        assert!(validate_base_url("ftp://hub.example.com").is_err());
        // 形似本机的主机名、userinfo 伪装都不能绕过 https 要求
        assert!(validate_base_url("http://localhost.evil.example").is_err());
        assert!(validate_base_url("http://127.0.0.1.evil.example").is_err());
        assert!(validate_base_url("http://localhost@evil.example").is_err());
        assert!(validate_base_url("http://evil.example/localhost").is_err());
        assert!(validate_base_url("https://").is_err());
    }

    /// 一份完整且合法的环境变量，测试里逐项篡改。
    fn valid_env() -> Vec<(&'static str, String)> {
        use base64::Engine;
        vec![
            ("DATABASE_URL", "postgres://u:p@127.0.0.1:5432/db".into()),
            ("PUBLIC_BASE_URL", "https://hub.example.com".into()),
            ("KEY_PEPPER", "k".repeat(32)),
            ("EMAIL_HASH_SECRET", "e".repeat(32)),
            ("IP_HASH_SECRET", "i".repeat(32)),
            (
                "EMAIL_ENC_KEY",
                base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            ),
        ]
    }

    fn load(env: &[(&'static str, String)]) -> Result<Config, String> {
        let map: std::collections::HashMap<&str, String> = env.iter().cloned().collect();
        Config::from_lookup(&|key| map.get(key).cloned())
    }

    fn with(
        env: &[(&'static str, String)],
        key: &'static str,
        value: &str,
    ) -> Vec<(&'static str, String)> {
        let mut env: Vec<_> = env.iter().filter(|(k, _)| *k != key).cloned().collect();
        env.push((key, value.to_string()));
        env
    }

    #[test]
    fn required_variables_are_reported() {
        assert!(load(&valid_env()).is_ok());
        let error = load(&[]).unwrap_err();
        for key in [
            "DATABASE_URL",
            "PUBLIC_BASE_URL",
            "KEY_PEPPER",
            "EMAIL_HASH_SECRET",
            "IP_HASH_SECRET",
            "EMAIL_ENC_KEY",
        ] {
            assert!(error.contains(key), "缺失提示应包含 {key}：{error}");
        }
        // 空白值等同于未设置
        let blank = with(&valid_env(), "KEY_PEPPER", "   ");
        assert!(load(&blank).unwrap_err().contains("KEY_PEPPER"));
    }

    #[test]
    fn weak_or_duplicate_secrets_are_rejected() {
        let env = valid_env();
        for key in ["KEY_PEPPER", "EMAIL_HASH_SECRET", "IP_HASH_SECRET"] {
            let short = with(&env, key, &"x".repeat(31));
            assert!(load(&short).unwrap_err().contains("32"), "{key} 过短应拒绝");
            let placeholder = with(&env, key, "change-me-change-me-change-me-change-me");
            assert!(
                load(&placeholder).unwrap_err().contains("change-me"),
                "{key} 含 change-me 应拒绝"
            );
        }
        let same = with(&env, "IP_HASH_SECRET", &"k".repeat(32));
        assert!(load(&same).unwrap_err().contains("互不相同"));
        // 全零加密密钥与长度不对的密钥
        let zero_key = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode([0u8; 32])
        };
        assert!(load(&with(&env, "EMAIL_ENC_KEY", &zero_key))
            .unwrap_err()
            .contains("全零"));
        let short_key = with(&env, "EMAIL_ENC_KEY", "AQID");
        assert!(load(&short_key).unwrap_err().contains("32 字节"));
        let not_base64 = with(&env, "EMAIL_ENC_KEY", "***");
        assert!(load(&not_base64).unwrap_err().contains("base64"));
    }

    #[test]
    fn unrecognized_bool_is_an_error() {
        let env = valid_env();
        for bad in ["ture", "flase", "enabled", "2"] {
            let error = load(&with(&env, "SMTP_VALIDATE_CERTS", bad)).unwrap_err();
            assert!(error.contains("SMTP_VALIDATE_CERTS"), "{bad}：{error}");
            assert!(load(&with(&env, "TRUST_CF_CONNECTING_IP", bad)).is_err());
        }
        for good in ["true", "TRUE", "1", "yes", "on"] {
            assert!(
                load(&with(&env, "SMTP_VALIDATE_CERTS", good))
                    .unwrap()
                    .smtp
                    .validate_certs
            );
        }
        for good in ["false", "False", "0", "no", "off"] {
            assert!(
                !load(&with(&env, "SMTP_VALIDATE_CERTS", good))
                    .unwrap()
                    .smtp
                    .validate_certs
            );
        }
        // 未设置时取默认值：校验证书、信任 CF 头
        let defaults = load(&env).unwrap();
        assert!(defaults.smtp.validate_certs);
        assert!(defaults.trust_cf_connecting_ip);
    }

    #[test]
    fn debug_output_masks_every_secret() {
        let mut env = valid_env();
        env.push(("SMTP_PASSWORD", "smtp-password-value".into()));
        env.push(("CLOUDFLARE_EMAIL_API_TOKEN", "cf-token-value".into()));
        let config = load(&env).unwrap();
        let rendered = format!("{config:?} {:?}", config.secrets);
        for (key, value) in &env {
            if matches!(
                *key,
                "DATABASE_URL"
                    | "KEY_PEPPER"
                    | "EMAIL_HASH_SECRET"
                    | "IP_HASH_SECRET"
                    | "EMAIL_ENC_KEY"
                    | "SMTP_PASSWORD"
                    | "CLOUDFLARE_EMAIL_API_TOKEN"
            ) {
                assert!(!rendered.contains(value.as_str()), "Debug 输出泄露了 {key}");
            }
        }
        // 32 字节密钥的数组形式也不能出现
        assert!(!rendered.contains("7, 7, 7"));
    }

    #[test]
    fn public_base_url_must_be_https_outside_loopback() {
        let env = valid_env();
        assert!(load(&with(&env, "PUBLIC_BASE_URL", "http://hub.example.com")).is_err());
        assert!(load(&with(&env, "PUBLIC_BASE_URL", "http://localhost:8787")).is_ok());
        let config = load(&with(&env, "PUBLIC_BASE_URL", "https://hub.example.com/")).unwrap();
        assert_eq!(config.public_base_url, "https://hub.example.com");
    }

    #[test]
    fn spoofable_header_warning_condition() {
        let env = valid_env();
        let loopback = load(&env).unwrap();
        assert!(
            !loopback.trusts_spoofable_ip_header(),
            "默认监听回环不应告警"
        );

        let exposed = load(&with(&env, "BIND_ADDR", "0.0.0.0:8787")).unwrap();
        assert!(exposed.trusts_spoofable_ip_header());
        let exposed_v6 = load(&with(&env, "BIND_ADDR", "[::]:8787")).unwrap();
        assert!(exposed_v6.trusts_spoofable_ip_header());

        let exposed_untrusted = {
            let env = with(&env, "BIND_ADDR", "0.0.0.0:8787");
            load(&with(&env, "TRUST_CF_CONNECTING_IP", "false")).unwrap()
        };
        assert!(!exposed_untrusted.trusts_spoofable_ip_header());
    }

    #[test]
    fn account_quota_and_numeric_settings() {
        let env = valid_env();
        let defaults = load(&env).unwrap();
        assert_eq!(defaults.account_create_per_hour, 100);
        assert_eq!(defaults.account_template_limit, 1000);
        assert_eq!(defaults.rate_limits.auth_failure_per_min, 30);

        let tuned = {
            let env = with(&env, "ACCOUNT_CREATE_PER_HOUR", "7");
            let env = with(&env, "ACCOUNT_TEMPLATE_LIMIT", "33");
            load(&with(&env, "RATE_AUTH_FAILURE_PER_MIN", "9")).unwrap()
        };
        assert_eq!(tuned.account_create_per_hour, 7);
        assert_eq!(tuned.account_template_limit, 33);
        assert_eq!(tuned.rate_limits.auth_failure_per_min, 9);

        assert!(load(&with(&env, "ACCOUNT_CREATE_PER_HOUR", "0")).is_err());
        assert!(load(&with(&env, "ACCOUNT_TEMPLATE_LIMIT", "-1")).is_err());
        assert!(load(&with(&env, "ACCOUNT_TEMPLATE_LIMIT", "many")).is_err());
        assert!(load(&with(&env, "RATE_AUTH_FAILURE_PER_MIN", "0")).is_err());
    }

    /// 样例配置照抄不能启动（密钥项留空），补上密钥后其余取值都合法。
    #[test]
    fn env_example_cannot_start_as_is() {
        let example: std::collections::HashMap<String, String> = include_str!("../.env.example")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| line.split_once('='))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect();
        let as_is = Config::from_lookup(&|key| example.get(key).cloned());
        let error = as_is.expect_err("照抄 .env.example 不应能启动");
        for key in [
            "KEY_PEPPER",
            "EMAIL_HASH_SECRET",
            "IP_HASH_SECRET",
            "EMAIL_ENC_KEY",
        ] {
            assert!(error.contains(key), "样例里 {key} 应留空：{error}");
        }

        // 样例里出现过的每个配置项都能被解析（拼写错误的键不会被静默忽略）
        let filled = valid_env();
        let merged = Config::from_lookup(&|key| {
            filled
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.clone())
                .or_else(|| example.get(key).cloned())
        });
        assert!(merged.is_ok(), "补全密钥后样例应合法：{merged:?}");
    }

    #[test]
    fn revoke_token_roundtrip_and_rejects() {
        let mut config = Config::default();
        config.secrets.key_pepper = "revoke-token-test-pepper-0123456789ab".to_string();
        let key_id = uuid::Uuid::new_v4();

        let token = config.revoke_token(key_id);
        assert_eq!(config.verify_revoke_token(&token), Some(key_id));

        // 换一把密钥的 ID：MAC 对不上
        let other = config.revoke_token(uuid::Uuid::new_v4());
        let other_id = other.split('.').next().unwrap().to_string();
        let my_mac = token.split('.').nth(1).unwrap();
        assert_eq!(
            config.verify_revoke_token(&format!("{other_id}.{my_mac}")),
            None
        );
        // 篡改 MAC 末位
        let mut tampered = token.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'a' { 'b' } else { 'a' });
        assert_eq!(config.verify_revoke_token(&tampered), None);
        // 空、乱码、缺段
        assert_eq!(config.verify_revoke_token(""), None);
        assert_eq!(config.verify_revoke_token("garbage"), None);
        assert_eq!(config.verify_revoke_token("no-mac-here-at-all"), None);
        // 胡乱 id 段
        assert_eq!(config.verify_revoke_token("not-a-uuid.deadbeef"), None);
        // 不同 pepper 无法通过
        config.secrets.key_pepper = "another-pepper-value-0123456789abcdef".to_string();
        assert_eq!(config.verify_revoke_token(&token), None);
    }

    #[test]
    fn smtp_normalization() {
        assert_eq!(normalize_smtp_encryption("auto"), SmtpEncryption::Auto);
        assert_eq!(normalize_smtp_encryption("plain"), SmtpEncryption::None);
        assert_eq!(normalize_smtp_encryption("none"), SmtpEncryption::None);
        assert_eq!(
            normalize_smtp_encryption("START_TLS"),
            SmtpEncryption::StartTls
        );
        assert_eq!(
            normalize_smtp_encryption("starttls"),
            SmtpEncryption::StartTls
        );
        assert_eq!(normalize_smtp_encryption("ssl"), SmtpEncryption::SslTls);
        assert_eq!(normalize_smtp_encryption("TLS"), SmtpEncryption::SslTls);
        assert_eq!(normalize_smtp_encryption("ssl_tls"), SmtpEncryption::SslTls);
        assert_eq!(normalize_smtp_encryption("weird"), SmtpEncryption::Auto);
        assert_eq!(normalize_smtp_encryption(""), SmtpEncryption::Auto);

        assert_eq!(normalize_smtp_auth_method("auto"), SmtpAuthMethod::Auto);
        assert_eq!(normalize_smtp_auth_method("login"), SmtpAuthMethod::Login);
        assert_eq!(normalize_smtp_auth_method("plain"), SmtpAuthMethod::Plain);
        assert_eq!(normalize_smtp_auth_method("none"), SmtpAuthMethod::None);
        assert_eq!(normalize_smtp_auth_method("bogus"), SmtpAuthMethod::Auto);
    }
}
