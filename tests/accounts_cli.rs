//! 命令行（真实二进制子进程）与账号封禁的测试，需要数据库；未设置 DATABASE_URL 时跳过。

mod common;

fn key_from_stdout(stdout: &str) -> String {
    stdout
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("iph_"))
        .unwrap_or_else(|| panic!("命令行输出里没有密钥：{stdout}"))
        .to_string()
}

/// admin create-key / ban / unban 的完整往返，且命令行的封禁在服务端立即生效。
#[tokio::test]
async fn cli_create_key_ban_and_unban_roundtrip() {
    let Some(app) = common::setup(|_| {}).await else {
        return;
    };

    let created = app
        .cli(
            &[
                "admin",
                "create-key",
                "--email",
                "Cli.User@qq.com",
                "--scopes",
                "read,write",
            ],
            None,
        )
        .await;
    assert!(created.success, "create-key 失败：{}", created.stderr);
    let key = key_from_stdout(&created.stdout);
    let info = app
        .client
        .get(app.url("/v1/key"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(info.status(), 200);

    // 给账号一个已公开的模板，--hide-templates 才有对象
    let template = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&serde_json::json!({"name": "命令行封禁", "content": "内容 {{input}}"}))
        .send()
        .await
        .unwrap();
    assert_eq!(template.status(), 201);
    let template: serde_json::Value = template.json().await.unwrap();
    let template_id = template["id"].as_str().unwrap().to_string();

    // 不带 --reason 或理由为空都不能执行
    let missing_reason = app
        .cli(&["admin", "ban", "--email", "cli.user@qq.com"], None)
        .await;
    assert!(!missing_reason.success);
    let blank_reason = app
        .cli(
            &[
                "admin",
                "ban",
                "--email",
                "cli.user@qq.com",
                "--reason",
                "  ",
            ],
            None,
        )
        .await;
    assert!(!blank_reason.success);
    assert!(
        blank_reason.stderr.contains("理由"),
        "{}",
        blank_reason.stderr
    );

    // 封禁（邮箱写法不同但身份相同）：吊销密钥并隐藏模板
    let banned = app
        .cli(
            &[
                "admin",
                "ban",
                "--email",
                "cli.user+tag@qq.com",
                "--hide-templates",
                "--reason",
                "命令行测试封禁",
            ],
            None,
        )
        .await;
    assert!(banned.success, "ban 失败：{}", banned.stderr);
    assert!(
        banned.stdout.contains("吊销 1 把密钥，隐藏 1 个模板"),
        "{}",
        banned.stdout
    );
    assert_eq!(
        app.client
            .get(app.url("/v1/key"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        app.client
            .get(app.url(&format!("/v1/templates/{template_id}")))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "被隐藏的模板详情不再公开"
    );

    // 封禁期间：命令行拒绝为该账号创建密钥，邮箱申请不发信、确认被拒
    let refused = app
        .cli(&["admin", "create-key", "--email", "cli.user@qq.com"], None)
        .await;
    assert!(!refused.success);
    assert!(refused.stderr.contains("封禁"), "{}", refused.stderr);
    let mails_before = app.mailer.mails().await.len();
    assert_eq!(app.request_key("cli.user@qq.com").await.status(), 202);
    assert_eq!(
        app.mailer.mails().await.len(),
        mails_before,
        "封禁邮箱不发信"
    );

    // 解封：不恢复模板；再次解封提示不在名单中；之后可以重新创建密钥
    let unbanned = app
        .cli(&["admin", "unban", "--email", "cli.user@qq.com"], None)
        .await;
    assert!(unbanned.success, "{}", unbanned.stderr);
    assert!(
        unbanned.stdout.contains("已解除封禁"),
        "{}",
        unbanned.stdout
    );
    let again = app
        .cli(&["admin", "unban", "--email", "cli.user@qq.com"], None)
        .await;
    assert!(again.success);
    assert!(again.stdout.contains("不在封禁名单"), "{}", again.stdout);
    assert_eq!(
        app.client
            .get(app.url(&format!("/v1/templates/{template_id}")))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "解封不自动恢复模板"
    );
    let recreated = app
        .cli(&["admin", "create-key", "--email", "cli.user@qq.com"], None)
        .await;
    assert!(recreated.success, "{}", recreated.stderr);
    assert_ne!(key_from_stdout(&recreated.stdout), key);
}

/// 命令行吊销单把密钥。
#[tokio::test]
async fn cli_revoke_key_by_id() {
    let Some(app) = common::setup(|_| {}).await else {
        return;
    };
    let key = app.create_key_direct("revoke-cli@qq.com", &["read"]).await;
    let key_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM api_keys WHERE email_hmac = $1 AND status = 'active'")
            .bind(app.state.config.account_hmac("revoke-cli@qq.com"))
            .fetch_one(&app.state.pool)
            .await
            .unwrap();

    let output = app
        .cli(
            &["admin", "revoke-key", "--key-id", &key_id.to_string()],
            None,
        )
        .await;
    assert!(output.success, "{}", output.stderr);
    assert_eq!(
        app.client
            .get(app.url("/v1/key"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let unknown = app
        .cli(
            &[
                "admin",
                "revoke-key",
                "--key-id",
                &uuid::Uuid::new_v4().to_string(),
            ],
            None,
        )
        .await;
    assert!(!unknown.success);
}

/// 服务运行时索引写锁被占用，reindex 明确提示先停服务；服务停止后（换一个空目录模拟）可以重建，
/// 并且不生成目录快照文件。
#[tokio::test]
async fn cli_reindex_requires_the_service_to_be_stopped() {
    let Some(app) = common::setup(|_| {}).await else {
        return;
    };
    let key = app
        .create_key_direct("reindex@qq.com", &["read", "write"])
        .await;
    let created = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&serde_json::json!({"name": "重建索引", "content": "内容 {{input}}"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);

    // 与运行中的服务共用 DATA_DIR：写锁被占用
    let busy = app.cli(&["reindex"], None).await;
    assert!(!busy.success);
    assert!(
        busy.stderr.contains("请先停止服务"),
        "应明确提示先停服务：{}",
        busy.stderr
    );

    // 空目录可以重建（等价于服务停止后）
    let dir = tempfile::tempdir().unwrap();
    let rebuilt = app.cli(&["reindex"], Some(dir.path())).await;
    assert!(rebuilt.success, "{}", rebuilt.stderr);
    assert!(
        rebuilt.stdout.contains("检索索引已重建（1 条）"),
        "{}",
        rebuilt.stdout
    );
    assert!(
        !dir.path().join("catalog").exists(),
        "reindex 不应生成目录快照文件"
    );
}

/// 缺少必填配置或密钥过弱时拒绝启动并给出明确提示（不需要数据库）。
#[tokio::test]
async fn cli_refuses_to_start_with_missing_or_weak_configuration() {
    let run = |envs: Vec<(&'static str, &'static str)>| async move {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_image-prompt-hub"));
        command.arg("migrate").env_clear();
        for (key, value) in envs {
            command.env(key, value);
        }
        command.output().await.unwrap()
    };

    let missing = run(vec![]).await;
    assert_eq!(missing.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(stderr.contains("缺少必填环境变量"), "{stderr}");

    let weak = run(vec![
        ("DATABASE_URL", "postgres://u:p@127.0.0.1:1/db"),
        ("PUBLIC_BASE_URL", "https://hub.example.com"),
        ("KEY_PEPPER", "too-short"),
        ("EMAIL_HASH_SECRET", "too-short-too"),
        ("IP_HASH_SECRET", "too-short-three"),
        (
            "EMAIL_ENC_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
    ])
    .await;
    assert_eq!(weak.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&weak.stderr).contains("32"));
}
