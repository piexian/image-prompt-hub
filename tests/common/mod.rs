//! 集成测试基础设施：每个测试独立的数据库、端口与服务实例。
//! 未设置 DATABASE_URL 时测试直接跳过。
//!
//! 测试不依赖真实时钟：验证邮件冷却用 `backdate_verifications` 直接改库时间绕过，
//! 默认限流额度放得足够大，需要触发限流的测试再显式调小。
#![allow(dead_code)]

use std::sync::Arc;

use image_prompt_hub::api;
use image_prompt_hub::config::{Config, RateLimitConfig, Secrets};
use image_prompt_hub::email::FakeMailer;
use image_prompt_hub::state::{build_state, AppState};
use rand::RngCore;
use sqlx::postgres::PgPoolOptions;
use sqlx::AssertSqlSafe;
use uuid::Uuid;

/// 命令行子进程的执行结果。
pub struct CliOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub struct TestApp {
    pub base_url: String,
    pub client: reqwest::Client,
    pub mailer: FakeMailer,
    pub state: AppState,
    schema: String,
    admin_url: String,
    server: Option<tokio::task::JoinHandle<()>>,
}

static TRACING_INIT: std::sync::Once = std::sync::Once::new();

fn init_tracing_for_tests() {
    TRACING_INIT.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        // 默认只输出 warn 及以上，避免 sqlx/hyper 的逐条日志淹没失败信息；RUST_LOG 可覆盖
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_writer(tracing_subscriber::fmt::TestWriter::new())
            .with_target(false)
            .with_level(false);
        let subscriber = tracing_subscriber::Registry::default()
            .with(filter)
            .with(fmt_layer);
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

/// 建独立 schema 并启动服务；DATABASE_URL 未设置时返回 None（跳过测试）。
///
/// 每个测试一个 schema 而不是一个数据库：`DROP DATABASE` 会强制做一次检查点，
/// 测试并发收尾时被串行化，既慢又容易在进程退出前来不及清理；`DROP SCHEMA` 是即时的。
pub async fn setup(adjust: impl FnOnce(&mut Config)) -> Option<TestApp> {
    init_tracing_for_tests();
    let Ok(admin_url) = std::env::var("DATABASE_URL") else {
        eprintln!("跳过：未设置 DATABASE_URL（集成测试需要 PostgreSQL）");
        return None;
    };
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .expect("连接测试数据库失败");

    let schema = format!("iph_test_{}", Uuid::new_v4().simple());
    sqlx::query(AssertSqlSafe(
        format!(r#"CREATE SCHEMA "{schema}""#).as_str(),
    ))
    .execute(&admin)
    .await
    .expect("创建测试 schema 失败");
    admin.close().await;

    let mut config = test_config(&url_with_search_path(&admin_url, &schema));
    adjust(&mut config);

    let mailer = FakeMailer::new();
    let state = build_state(config, Arc::new(mailer.clone()))
        .await
        .expect("构建服务状态失败");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定随机端口失败");
    let addr = listener.local_addr().expect("读取端口失败");
    let router = api::router(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("测试服务异常退出");
    });

    Some(TestApp {
        base_url: format!("http://{addr}"),
        client: reqwest::Client::builder()
            .build()
            .expect("构建 HTTP 客户端失败"),
        mailer,
        state,
        schema,
        admin_url,
        server: Some(server),
    })
}

/// 给连接串追加 `options=-c search_path=<schema>`，该连接串打开的每个连接都落在测试 schema 里。
fn url_with_search_path(url: &str, schema: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}options=-c%20search_path%3D{schema}")
}

fn test_config(database_url: &str) -> Config {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    // 默认额度放到足够大：触发限流的测试自己调小，其余测试不受请求节奏影响
    let generous = 1_000_000;
    Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        data_dir: std::env::temp_dir().join(format!("iph-test-{}", Uuid::new_v4().simple())),
        public_base_url: "https://hub.test.example".to_string(),
        // 测试直连本机，不模拟 CF 头
        trust_cf_connecting_ip: false,
        secrets: Secrets {
            database_url: database_url.to_string(),
            key_pepper: format!("pepper-{}", Uuid::new_v4()),
            email_hash_secret: format!("email-{}", Uuid::new_v4()),
            ip_hash_secret: format!("ip-{}", Uuid::new_v4()),
            email_enc_key: key,
        },
        // 快照立即重新生成；邮箱冷却保持默认的 10 分钟，需要绕过时改库时间
        catalog_debounce_secs: 0,
        rate_limits: RateLimitConfig {
            anon_read_per_min: generous,
            keyed_read_per_min: generous,
            write_per_min: generous,
            key_request_per_hour: generous,
            key_verify_per_hour: generous,
            report_per_hour: generous,
            auth_attempt_per_min: generous,
        },
        ..Config::default()
    }
}

impl TestApp {
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// 从假发信器里取最新一封验证邮件并抽出令牌。
    pub async fn latest_verification_token(&self) -> String {
        let mails = self.mailer.mails().await;
        let mail = mails
            .iter()
            .rev()
            .find(|m| m.subject.contains("验证"))
            .expect("没有收到验证邮件");
        let marker = "/v1/keys/verify?token=";
        let start = mail.body.find(marker).expect("邮件里没有验证链接") + marker.len();
        mail.body[start..]
            .split_whitespace()
            .next()
            .expect("令牌为空")
            .to_string()
    }

    /// 从假发信器里取最新一封密钥邮件并抽出密钥。
    pub async fn latest_api_key(&self) -> String {
        let mails = self.mailer.mails().await;
        let mail = mails
            .iter()
            .rev()
            .find(|m| m.subject.contains("API 密钥"))
            .expect("没有收到密钥邮件");
        mail.body
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("iph_"))
            .expect("邮件里没有密钥")
            .to_string()
    }

    /// 走完整申请流程，返回新密钥。
    pub async fn issue_key(&self, email: &str) -> String {
        let response = self
            .client
            .post(self.url("/v1/keys/request"))
            .json(&serde_json::json!({"email": email}))
            .send()
            .await
            .expect("请求失败");
        if response.status() != 202 {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            panic!("申请验证邮件失败：{status} body={body}");
        }
        let token = self.latest_verification_token().await;
        let page = self
            .client
            .get(self.url(&format!("/v1/keys/verify?token={token}")))
            .send()
            .await
            .expect("打开确认页失败");
        assert_eq!(page.status(), 200);
        let confirm = self
            .client
            .post(self.url("/v1/keys/verify"))
            .form(&[("token", token.as_str())])
            .send()
            .await
            .expect("确认失败");
        assert_eq!(confirm.status(), 200);
        let body = confirm.text().await.unwrap_or_default();
        assert!(body.contains("密钥已发送到邮箱"), "确认页异常：{body}");
        self.latest_api_key().await
    }

    pub async fn request_key(&self, email: &str) -> reqwest::Response {
        self.client
            .post(self.url("/v1/keys/request"))
            .json(&serde_json::json!({"email": email}))
            .send()
            .await
            .expect("申请请求失败")
    }

    pub async fn confirm_token(&self, token: &str) -> reqwest::Response {
        self.client
            .post(self.url("/v1/keys/verify"))
            .form(&[("token", token)])
            .send()
            .await
            .expect("确认请求失败")
    }

    /// 某邮箱身份下指定状态的密钥数。
    pub async fn count_keys(&self, email: &str, status: &str) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM api_keys WHERE email_hmac = $1 AND status = $2")
            .bind(self.state.config.account_hmac(email))
            .bind(status)
            .fetch_one(&self.state.pool)
            .await
            .expect("统计密钥失败")
    }

    /// 以子进程方式运行真实的命令行二进制，连接本测试的数据库（密钥配置与服务一致）。
    pub async fn cli(&self, args: &[&str], data_dir: Option<&std::path::Path>) -> CliOutput {
        use base64::Engine;
        let config = &self.state.config;
        let data_dir = data_dir.unwrap_or(&config.data_dir);
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_image-prompt-hub"))
            .args(args)
            .env_clear()
            .env("DATABASE_URL", &config.secrets.database_url)
            .env("PUBLIC_BASE_URL", &config.public_base_url)
            .env("KEY_PEPPER", &config.secrets.key_pepper)
            .env("EMAIL_HASH_SECRET", &config.secrets.email_hash_secret)
            .env("IP_HASH_SECRET", &config.secrets.ip_hash_secret)
            .env(
                "EMAIL_ENC_KEY",
                base64::engine::general_purpose::STANDARD.encode(config.secrets.email_enc_key),
            )
            .env("DATA_DIR", data_dir)
            .output()
            .await
            .expect("运行命令行失败");
        CliOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// 把该邮箱最近的验证记录时间整体前移，绕过冷却窗口（代替睡眠等待）。
    pub async fn backdate_verifications(&self, email: &str) {
        let email_hmac = self.state.config.account_hmac(email);
        sqlx::query(
            "UPDATE email_verifications SET created_at = created_at - interval '1 hour'
             WHERE email_hmac = $1",
        )
        .bind(&email_hmac)
        .execute(&self.state.pool)
        .await
        .expect("前移验证记录时间失败");
    }

    /// 直接在库里创建一把 active 密钥（等价于 CLI admin create-key）。
    pub async fn create_key_direct(&self, email: &str, scopes: &[&str]) -> String {
        let key = image_prompt_hub::crypto::generate_api_key();
        let email_hmac = self.state.config.account_hmac(email);
        sqlx::query("UPDATE api_keys SET status = 'revoked', revoked_at = now() WHERE email_hmac = $1 AND status = 'active'")
            .bind(&email_hmac)
            .execute(&self.state.pool)
            .await
            .expect("吊销旧密钥失败");
        image_prompt_hub::api::keys::insert_active_key(
            &self.state.pool,
            &key,
            &self.state.config.key_hash(&key),
            &email_hmac,
            &scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .await
        .expect("创建密钥失败");
        key
    }

    /// 轮询检索结果（索引提交带约 1 秒合并窗口）。
    pub async fn wait_search(&self, q: &str, template_id: &str, expect_found: bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let response = self
                .client
                .get(self.url(&format!("/v1/templates?q={q}")))
                .send()
                .await
                .unwrap();
            let value: serde_json::Value = response.json().await.unwrap();
            let found = value["templates"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["id"].as_str() == Some(template_id));
            if found == expect_found {
                return;
            }
            if std::time::Instant::now() > deadline {
                panic!("等待检索结果超时：q={q} id={template_id} 期望出现={expect_found}");
            }
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
    }

    /// 轮询目录快照条数。
    pub async fn wait_catalog_count(&self, count: i64) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let response = self
                .client
                .get(self.url("/v1/catalog/version"))
                .send()
                .await
                .unwrap();
            let value: serde_json::Value = response.json().await.unwrap();
            if value["count"].as_i64() == Some(count) {
                return;
            }
            if std::time::Instant::now() > deadline {
                panic!("等待快照条数超时：期望 {count}，当前 {}", value["count"]);
            }
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.abort();
        }
        let schema = self.schema.clone();
        let admin_url = self.admin_url.clone();
        // 独立线程清理，不依赖测试运行时；等它结束，进程退出前不会留下临时 schema
        let cleanup = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("构建清理运行时失败");
            runtime.block_on(async move {
                if let Ok(admin) = sqlx::PgPool::connect(&admin_url).await {
                    // 锁等待设上限，清理失败只会留下一个 schema，不会卡住测试
                    let _ = sqlx::query("SET lock_timeout = '10s'")
                        .execute(&admin)
                        .await;
                    let _ = sqlx::query(AssertSqlSafe(
                        format!(r#"DROP SCHEMA IF EXISTS "{schema}" CASCADE"#).as_str(),
                    ))
                    .execute(&admin)
                    .await;
                    admin.close().await;
                }
            });
        });
        let _ = cleanup.join();
    }
}
