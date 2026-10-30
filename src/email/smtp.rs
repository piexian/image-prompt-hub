//! SMTP 发信（lettre + rustls）。加密方式映射：`starttls` 与 `auto`（非 465 端口）
//! 使用 STARTTLS（必需），`auto` 的 465 端口与 `ssl_tls` 用隐式 TLS，`none` 明文。
//! 不做机会式 STARTTLS：服务器不提供或被剥掉 STARTTLS 时账号密码会明文外泄，
//! 这一点与插件市场不同，需要明文的场景必须显式配置 `none`。

use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Tls, TlsParameters, TlsParametersBuilder};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::time::Duration;

use crate::config::{SmtpAuthMethod, SmtpEncryption};
use crate::email::Mailer;

const SEND_TIMEOUT: Duration = Duration::from_secs(10);

pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl SmtpMailer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        from: &str,
        from_name: &str,
        encryption: SmtpEncryption,
        auth_method: SmtpAuthMethod,
        validate_certs: bool,
    ) -> Result<Self, String> {
        if host.is_empty() {
            return Err("SMTP_HOST 未配置".to_string());
        }
        let from_mailbox = build_mailbox(from, from_name)?;
        let transport = Self::build_transport(
            host,
            port,
            username,
            password,
            encryption,
            auth_method,
            validate_certs,
        )?;
        Ok(Self {
            transport,
            from: from_mailbox,
        })
    }

    fn build_transport(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        encryption: SmtpEncryption,
        auth_method: SmtpAuthMethod,
        validate_certs: bool,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
            .port(port)
            .tls(build_tls(encryption, port, host, validate_certs)?);

        if !username.is_empty() && auth_method != SmtpAuthMethod::None {
            builder =
                builder.credentials(Credentials::new(username.to_string(), password.to_string()));
            builder = match auth_method {
                SmtpAuthMethod::Login => builder.authentication(vec![Mechanism::Login]),
                SmtpAuthMethod::Plain => builder.authentication(vec![Mechanism::Plain]),
                _ => builder,
            };
        }
        Ok(builder.build())
    }
}

/// 把加密方式映射为 lettre 的 TLS 模式。隐式 TLS 与必需 STARTTLS 共用同一份证书校验参数，
/// 都遵守 `validate_certs`。
pub fn build_tls(
    encryption: SmtpEncryption,
    port: u16,
    host: &str,
    validate_certs: bool,
) -> Result<Tls, String> {
    let parameters = || -> Result<TlsParameters, String> {
        TlsParametersBuilder::new(host.to_string())
            .dangerous_accept_invalid_certs(!validate_certs)
            .build()
            .map_err(|e| e.to_string())
    };
    Ok(match tls_mode(encryption, port) {
        TlsMode::Wrapper => Tls::Wrapper(parameters()?),
        TlsMode::RequiredStartTls => Tls::Required(parameters()?),
        TlsMode::None => Tls::None,
    })
}

/// 加密方式与端口到 TLS 模式的映射（可单测）。
pub fn tls_mode(encryption: SmtpEncryption, port: u16) -> TlsMode {
    match encryption {
        SmtpEncryption::SslTls => TlsMode::Wrapper,
        // auto：465 是隐式 TLS 端口，其余端口一律要求 STARTTLS
        SmtpEncryption::Auto if port == 465 => TlsMode::Wrapper,
        SmtpEncryption::Auto | SmtpEncryption::StartTls => TlsMode::RequiredStartTls,
        SmtpEncryption::None => TlsMode::None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// 隐式 TLS（连接即 TLS，465）。
    Wrapper,
    /// 必需的 STARTTLS（587 等）。
    RequiredStartTls,
    /// 明文连接，仅在显式配置 none 时使用。
    None,
}

fn build_mailbox(from: &str, from_name: &str) -> Result<Mailbox, String> {
    let address = from
        .parse()
        .map_err(|_| format!("SMTP_FROM 不是有效的邮箱地址：{from}"))?;
    if from_name.is_empty() {
        Ok(Mailbox::new(None, address))
    } else {
        Ok(Mailbox::new(Some(from_name.to_string()), address))
    }
}

#[async_trait]
impl Mailer for SmtpMailer {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        let to_mailbox = to.parse().map_err(|_| "收件地址无效".to_string())?;
        let message = Message::builder()
            .from(self.from.clone())
            .to(to_mailbox)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body.to_string())
            .map_err(|e| format!("构造邮件失败：{e}"))?;
        let result = tokio::time::timeout(SEND_TIMEOUT, self.transport.send(message)).await;
        match result {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => Err(format!("SMTP 发送失败：{error}")),
            Err(_) => Err("SMTP 发送超时（10 秒）".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_mode_mapping() {
        // 显式 ssl_tls 任何端口都是隐式 TLS
        assert_eq!(tls_mode(SmtpEncryption::SslTls, 587), TlsMode::Wrapper);
        assert_eq!(tls_mode(SmtpEncryption::SslTls, 465), TlsMode::Wrapper);
        // starttls 任何端口都是必需 STARTTLS
        assert_eq!(
            tls_mode(SmtpEncryption::StartTls, 587),
            TlsMode::RequiredStartTls
        );
        assert_eq!(
            tls_mode(SmtpEncryption::StartTls, 465),
            TlsMode::RequiredStartTls
        );
        // auto：465 隐式 TLS，其余必需 STARTTLS（不做机会式）
        assert_eq!(tls_mode(SmtpEncryption::Auto, 465), TlsMode::Wrapper);
        assert_eq!(
            tls_mode(SmtpEncryption::Auto, 587),
            TlsMode::RequiredStartTls
        );
        assert_eq!(
            tls_mode(SmtpEncryption::Auto, 25),
            TlsMode::RequiredStartTls
        );
        // none：明文
        assert_eq!(tls_mode(SmtpEncryption::None, 25), TlsMode::None);
    }

    /// 四种加密方式（含 auto 的 465 与其他端口）各自映射到的 lettre `Tls` 模式。
    #[test]
    fn encryption_maps_to_lettre_tls_modes() {
        for validate_certs in [true, false] {
            let tls = |encryption, port| {
                build_tls(encryption, port, "smtp.example.com", validate_certs)
                    .expect("构造 TLS 参数不应失败")
            };
            // ssl_tls：任何端口都是隐式 TLS（含 587，由用户显式选择）
            assert!(matches!(tls(SmtpEncryption::SslTls, 465), Tls::Wrapper(_)));
            assert!(matches!(tls(SmtpEncryption::SslTls, 587), Tls::Wrapper(_)));
            // starttls：任何端口都是必需 STARTTLS，且遵守 validate_certs（不能走隐式 TLS）
            assert!(matches!(
                tls(SmtpEncryption::StartTls, 587),
                Tls::Required(_)
            ));
            assert!(matches!(
                tls(SmtpEncryption::StartTls, 465),
                Tls::Required(_)
            ));
            // auto：465 隐式 TLS，其余必需 STARTTLS
            assert!(matches!(tls(SmtpEncryption::Auto, 465), Tls::Wrapper(_)));
            assert!(matches!(tls(SmtpEncryption::Auto, 587), Tls::Required(_)));
            assert!(matches!(tls(SmtpEncryption::Auto, 25), Tls::Required(_)));
            // none：明文，只在显式配置时出现
            assert!(matches!(tls(SmtpEncryption::None, 25), Tls::None));
        }
    }

    /// 任何组合都不会落到机会式 STARTTLS：服务器不提供或被剥掉 STARTTLS 时会明文外泄账号密码。
    #[test]
    fn never_opportunistic_and_only_none_is_plaintext() {
        for encryption in [
            SmtpEncryption::Auto,
            SmtpEncryption::StartTls,
            SmtpEncryption::SslTls,
            SmtpEncryption::None,
        ] {
            for port in [25, 465, 587, 2525] {
                let tls = build_tls(encryption, port, "smtp.example.com", true).unwrap();
                assert!(
                    !matches!(tls, Tls::Opportunistic(_)),
                    "{encryption:?}/{port}"
                );
                assert_eq!(
                    matches!(tls, Tls::None),
                    encryption == SmtpEncryption::None,
                    "只有显式 none 才允许明文：{encryption:?}/{port}"
                );
            }
        }
    }

    #[test]
    fn transport_builds_for_every_combination() {
        for validate in [true, false] {
            for encryption in [
                SmtpEncryption::Auto,
                SmtpEncryption::StartTls,
                SmtpEncryption::SslTls,
                SmtpEncryption::None,
            ] {
                let transport = SmtpMailer::build_transport(
                    "smtp.example.com",
                    587,
                    "user",
                    "pass",
                    encryption,
                    SmtpAuthMethod::Auto,
                    validate,
                );
                assert!(transport.is_ok(), "{encryption:?} validate={validate}");
            }
        }
        // 不认证
        assert!(SmtpMailer::build_transport(
            "smtp.example.com",
            25,
            "",
            "",
            SmtpEncryption::None,
            SmtpAuthMethod::None,
            true,
        )
        .is_ok());
    }
}
