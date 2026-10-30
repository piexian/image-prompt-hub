//! SMTP 加密方式的行为测试：用本机假 SMTP 服务器确认实际的握手顺序，
//! 不连接任何外部服务，也不需要数据库。

use std::sync::{Arc, Mutex};

use image_prompt_hub::config::{SmtpAuthMethod, SmtpEncryption};
use image_prompt_hub::email::smtp::SmtpMailer;
use image_prompt_hub::email::Mailer;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// 假服务器的行为脚本。
#[derive(Clone, Copy)]
enum Script {
    /// EHLO 回应里宣告支持 STARTTLS；收到 STARTTLS 后答 220 并断开（客户端握手随之失败）。
    OfferStartTls,
    /// EHLO 回应里不含 STARTTLS，之后的命令一律按明文服务器处理。
    NoStartTls,
}

/// 启动只服务一个连接的假 SMTP 服务器，返回端口与收到的命令行记录。
async fn spawn_server(script: Script) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let server_log = log.clone();
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        let _ = write.write_all(b"220 fake ESMTP\r\n").await;
        let mut in_data = false;
        let mut line = String::new();
        loop {
            line.clear();
            // 客户端若直接发起隐式 TLS，这里读到的是二进制握手数据，read_line 返回错误并结束
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let text = line.trim_end().to_string();
            server_log.lock().unwrap().push(text.clone());
            if in_data {
                if text == "." {
                    in_data = false;
                    let _ = write.write_all(b"250 queued\r\n").await;
                }
                continue;
            }
            let upper = text.to_ascii_uppercase();
            let reply: &[u8] = if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                match script {
                    Script::OfferStartTls => b"250-fake\r\n250 STARTTLS\r\n",
                    Script::NoStartTls => b"250 fake\r\n",
                }
            } else if upper.starts_with("STARTTLS") {
                let _ = write.write_all(b"220 ready\r\n").await;
                break;
            } else if upper.starts_with("MAIL") || upper.starts_with("RCPT") {
                b"250 ok\r\n"
            } else if upper.starts_with("DATA") {
                in_data = true;
                b"354 go ahead\r\n"
            } else if upper.starts_with("QUIT") {
                let _ = write.write_all(b"221 bye\r\n").await;
                break;
            } else {
                b"502 not implemented\r\n"
            };
            let _ = write.write_all(reply).await;
        }
    });
    (port, log)
}

fn mailer(port: u16, encryption: SmtpEncryption, with_credentials: bool) -> SmtpMailer {
    let (username, password) = if with_credentials {
        ("user", "secret-password")
    } else {
        ("", "")
    };
    SmtpMailer::new(
        "127.0.0.1",
        port,
        username,
        password,
        "noreply@example.com",
        "模板服务",
        encryption,
        SmtpAuthMethod::Auto,
        true,
    )
    .expect("构造发信器失败")
}

fn commands(log: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    log.lock().unwrap().clone()
}

/// starttls 与 auto（非 465 端口）先明文握手并发出 STARTTLS 命令，而不是一上来就是隐式 TLS
/// （隐式 TLS 只用于 465 端口，在 587 上发起隐式 TLS 必然失败）。
#[tokio::test]
async fn starttls_and_auto_negotiate_starttls_in_plaintext_first() {
    for encryption in [SmtpEncryption::StartTls, SmtpEncryption::Auto] {
        let (port, log) = spawn_server(Script::OfferStartTls).await;
        let result = mailer(port, encryption, true)
            .send("user@qq.com", "主题", "正文")
            .await;
        // 假服务器在 220 之后断开，TLS 升级必然失败；这里只关心握手顺序
        assert!(result.is_err(), "{encryption:?}：升级失败时发送应报错");
        let seen = commands(&log);
        assert!(
            seen.iter()
                .any(|l| l.to_ascii_uppercase().starts_with("EHLO")),
            "{encryption:?}：应先以明文发 EHLO，实际：{seen:?}"
        );
        assert!(
            seen.iter().any(|l| l.eq_ignore_ascii_case("STARTTLS")),
            "{encryption:?}：应发出 STARTTLS 命令，实际：{seen:?}"
        );
        assert!(
            !seen
                .iter()
                .any(|l| l.to_ascii_uppercase().starts_with("AUTH")),
            "{encryption:?}：升级 TLS 之前不能发送认证"
        );
    }
}

/// 服务器不提供 STARTTLS（或被中间人剥掉）时，auto / starttls 必须拒绝继续，
/// 账号密码与邮件内容都不能以明文发出。
#[tokio::test]
async fn missing_starttls_is_refused_without_leaking_credentials() {
    for encryption in [SmtpEncryption::Auto, SmtpEncryption::StartTls] {
        let (port, log) = spawn_server(Script::NoStartTls).await;
        let result = mailer(port, encryption, true)
            .send("user@qq.com", "主题", "含有秘密的正文")
            .await;
        assert!(
            result.is_err(),
            "{encryption:?}：不支持 STARTTLS 时应拒绝发送"
        );
        let seen = commands(&log);
        for forbidden in ["AUTH", "MAIL", "RCPT", "DATA"] {
            assert!(
                !seen
                    .iter()
                    .any(|l| l.to_ascii_uppercase().starts_with(forbidden)),
                "{encryption:?}：不应出现 {forbidden}，实际：{seen:?}"
            );
        }
        assert!(
            !seen.iter().any(|l| l.contains("secret-password")),
            "密码不能出现在明文连接上"
        );
    }
}

/// 只有显式配置 none 才会走明文，并能完整投递。
#[tokio::test]
async fn explicit_none_delivers_in_plaintext() {
    let (port, log) = spawn_server(Script::NoStartTls).await;
    let result = mailer(port, SmtpEncryption::None, false)
        .send("user@qq.com", "主题", "正文")
        .await;
    assert!(result.is_ok(), "none 应能明文投递：{result:?}");
    let seen = commands(&log);
    for expected in [
        "MAIL FROM:<noreply@example.com>",
        "RCPT TO:<user@qq.com>",
        "DATA",
    ] {
        assert!(
            seen.iter().any(|line| line == expected),
            "应收到 {expected}，实际：{seen:?}"
        );
    }
}
