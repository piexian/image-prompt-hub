//! 命令行入口：serve / migrate / reindex / admin create-key / admin revoke-key。

use clap::{Parser, Subcommand};

use image_prompt_hub::config::{Config, LogFormat};
use image_prompt_hub::error::ApiError;
use image_prompt_hub::search::SearchIndex;
use image_prompt_hub::state::{build_state, connect_pool, run_migrations};
use image_prompt_hub::{accounts, api, crypto, validate};

#[derive(Parser)]
#[command(name = "image-prompt-hub", about = "在线提示词模板服务", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 启动 HTTP 服务
    Serve,
    /// 只执行数据库迁移
    Migrate,
    /// 从数据库重建检索索引
    Reindex,
    /// 管理命令
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

#[derive(Subcommand)]
enum AdminCommand {
    /// 直接创建一把 active 密钥并只在终端打印一次
    CreateKey {
        #[arg(long)]
        email: String,
        /// 逗号分隔，默认 read,write
        #[arg(long, value_delimiter = ',')]
        scopes: Option<Vec<String>>,
    },
    /// 吊销密钥
    RevokeKey {
        #[arg(long)]
        key_id: uuid::Uuid,
    },
    /// 封禁账号：吊销其全部密钥，可选隐藏其全部公开模板
    Ban {
        #[arg(long)]
        email: String,
        #[arg(long)]
        hide_templates: bool,
        #[arg(long)]
        reason: String,
    },
    /// 解除封禁（不自动恢复模板）
    Unban {
        #[arg(long)]
        email: String,
    },
}

fn init_tracing(format: LogFormat) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match format {
        LogFormat::Pretty => tracing_subscriber::fmt().with_env_filter(filter).init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
    }
}

#[tokio::main]
async fn main() {
    // 存在 .env 时加载（已设置的环境变量优先）
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("配置错误：{error}");
            std::process::exit(2);
        }
    };
    init_tracing(config.log_format);

    let result = match cli.command {
        Command::Serve => serve(config).await,
        Command::Migrate => migrate(config).await,
        Command::Reindex => reindex(config).await,
        Command::Admin { command } => match command {
            AdminCommand::CreateKey { email, scopes } => {
                admin_create_key(config, email, scopes).await
            }
            AdminCommand::RevokeKey { key_id } => admin_revoke_key(config, key_id).await,
            AdminCommand::Ban {
                email,
                hide_templates,
                reason,
            } => admin_ban(config, email, hide_templates, reason).await,
            AdminCommand::Unban { email } => admin_unban(config, email).await,
        },
    };
    if let Err(error) = result {
        eprintln!("执行失败：{}", error.message);
        std::process::exit(1);
    }
}

async fn serve(config: Config) -> Result<(), ApiError> {
    let mailer = match image_prompt_hub::email::build_mailer(config.email_provider, &config) {
        Ok(mailer) => mailer,
        Err(error) => {
            eprintln!("发信配置错误：{error}");
            std::process::exit(2);
        }
    };
    let state = build_state(config.clone(), mailer).await?;
    if state.config.trusts_spoofable_ip_header() {
        tracing::warn!(
            "监听地址不是回环且 TRUST_CF_CONNECTING_IP=true：直连的请求可以伪造 CF-Connecting-IP 头，\
             请确认只有 Cloudflare Tunnel 能连到服务，或改为 TRUST_CF_CONNECTING_IP=false"
        );
    }
    tracing::info!(addr = %state.config.bind_addr, "服务启动");

    let listener = tokio::net::TcpListener::bind(state.config.bind_addr)
        .await
        .map_err(|e| ApiError::internal_with(format!("监听端口失败：{e}")))?;
    let app =
        api::router(state.clone()).into_make_service_with_connect_info::<std::net::SocketAddr>();

    let shutdown = async {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("注册 SIGTERM 处理失败");
            tokio::select! {
                _ = ctrl_c => {},
                _ = term.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
        }
        tracing::info!("收到退出信号，正在关闭");
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|e| ApiError::internal_with(format!("服务运行失败：{e}")))?;
    Ok(())
}

async fn migrate(config: Config) -> Result<(), ApiError> {
    let pool = connect_pool(&config.secrets.database_url).await?;
    run_migrations(&pool).await?;
    println!("数据库迁移完成");
    Ok(())
}

async fn reindex(config: Config) -> Result<(), ApiError> {
    let pool = connect_pool(&config.secrets.database_url).await?;
    run_migrations(&pool).await?;
    // 服务运行时索引写锁被占用，open_dir 会返回“请先停止服务”的提示
    let (index, _queue) = SearchIndex::open_dir(&config.data_dir.join("index"))?;
    index.rebuild_from_db(&pool).await?;
    println!("检索索引已重建（{} 条）", index.doc_count());
    Ok(())
}

async fn admin_create_key(
    config: Config,
    email: String,
    scopes: Option<Vec<String>>,
) -> Result<(), ApiError> {
    let email = validate::normalize_email(&email);
    if !validate::is_valid_email_format(&email) {
        return Err(ApiError::bad_request("邮箱格式无效"));
    }
    let scopes: Vec<String> = scopes.unwrap_or_else(|| vec!["read".into(), "write".into()]);
    for scope in &scopes {
        if !["read", "write", "admin"].contains(&scope.as_str()) {
            return Err(ApiError::bad_request("scopes 只能是 read、write、admin"));
        }
    }
    let pool = connect_pool(&config.secrets.database_url).await?;
    run_migrations(&pool).await?;
    let key = crypto::generate_api_key();
    let email_hmac = config.account_hmac(&email);
    if accounts::is_banned(&pool, &email_hmac).await? {
        return Err(ApiError::bad_request(
            "该账号已被封禁，请先执行 admin unban 再创建密钥",
        ));
    }
    // 管理员创建不受白名单限制，同一邮箱重复创建前先吊销旧 active 密钥
    sqlx::query("UPDATE api_keys SET status = 'revoked', revoked_at = now() WHERE email_hmac = $1 AND status = 'active'")
        .bind(&email_hmac)
        .execute(&pool)
        .await
        .map_err(ApiError::from)?;
    let row = image_prompt_hub::api::keys::insert_active_key(
        &pool,
        &key,
        &config.key_hash(&key),
        &email_hmac,
        &scopes,
    )
    .await?;
    println!("密钥已创建（只显示这一次）：");
    println!("{key}");
    println!("ID：{}", row.id);
    Ok(())
}

async fn admin_revoke_key(config: Config, key_id: uuid::Uuid) -> Result<(), ApiError> {
    let pool = connect_pool(&config.secrets.database_url).await?;
    run_migrations(&pool).await?;
    let result =
        sqlx::query("UPDATE api_keys SET status = 'revoked', revoked_at = now() WHERE id = $1")
            .bind(key_id)
            .execute(&pool)
            .await
            .map_err(ApiError::from)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found());
    }
    println!("密钥已吊销");
    Ok(())
}

async fn admin_ban(
    config: Config,
    email: String,
    hide_templates: bool,
    reason: String,
) -> Result<(), ApiError> {
    let reason = reason.trim();
    if reason.is_empty() || reason.chars().count() > 500 || validate::has_forbidden_control(reason)
    {
        return Err(ApiError::bad_request("理由必须是 1 到 500 字的文本"));
    }
    let pool = connect_pool(&config.secrets.database_url).await?;
    run_migrations(&pool).await?;
    let outcome =
        accounts::ban(&pool, &config.account_hmac(&email), reason, hide_templates).await?;
    println!(
        "已封禁账号：吊销 {} 把密钥，隐藏 {} 个模板",
        outcome.revoked_keys,
        outcome.hidden_template_ids.len()
    );
    if !outcome.hidden_template_ids.is_empty() {
        println!(
            "提示：命令行不会通知运行中的服务，被隐藏的模板要等服务重启后才会从检索索引和目录快照里消失；\
             服务运行时请优先使用 POST /v1/admin/accounts/ban。"
        );
    }
    Ok(())
}

async fn admin_unban(config: Config, email: String) -> Result<(), ApiError> {
    let pool = connect_pool(&config.secrets.database_url).await?;
    run_migrations(&pool).await?;
    if accounts::unban(&pool, &config.account_hmac(&email)).await? {
        println!("已解除封禁（模板不会自动恢复，需要用管理接口逐个恢复）");
    } else {
        println!("该账号不在封禁名单中");
    }
    Ok(())
}
