//! 需要数据库的集成测试。未设置 DATABASE_URL 时全部跳过。
//! 不依赖真实时钟：等待冷却用改库时间代替睡眠。

mod common;

use common::TestApp;
use image_prompt_hub::config::Config;

/// 有库才跑；无库时输出跳过原因后直接返回。
async fn app() -> Option<TestApp> {
    common::setup(|_| {}).await
}

async fn app_with(adjust: impl FnOnce(&mut Config)) -> Option<TestApp> {
    common::setup(adjust).await
}

#[tokio::test]
async fn full_key_request_flow() {
    let Some(app) = app().await else { return };

    // 申请
    let response = app
        .client
        .post(app.url("/v1/keys/request"))
        .json(&serde_json::json!({"email": "User@QQ.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 202);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["error"].is_null());

    app.wait_mail_tasks().await;
    let mails = app.mailer.mails().await;
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0].to, "user@qq.com", "邮箱应已规范化");
    assert!(mails[0].body.contains("申请"), "首封应是申请措辞");

    let token = app.latest_verification_token().await;
    assert!(token.len() > 30);

    // 打开确认页不改变状态
    let page = app
        .client
        .get(app.url(&format!("/v1/keys/verify?token={token}")))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    assert!(html.contains("确认申请密钥"), "确认页缺少说明：{html}");
    for header in [
        "content-security-policy",
        "x-frame-options",
        "referrer-policy",
        "cache-control",
    ] {
        assert!(
            page_has_header(&app, &token, header).await,
            "确认页缺少响应头 {header}"
        );
    }
    let used: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT used_at FROM email_verifications WHERE token_hash = $1")
            .bind(image_prompt_hub::crypto::sha256_hex(token.as_bytes()))
            .fetch_one(&app.state.pool)
            .await
            .unwrap();
    assert!(used.is_none(), "打开确认页不应消耗令牌");

    // 确认后拿到密钥
    let confirm = app
        .client
        .post(app.url("/v1/keys/verify"))
        .form(&[("token", token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(confirm.status(), 200);
    assert!(confirm.text().await.unwrap().contains("密钥已发送到邮箱"));

    let key = app.latest_api_key().await;
    assert!(key.starts_with("iph_"));

    // 密钥可用
    let info = app
        .client
        .get(app.url("/v1/key"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(info.status(), 200);
    let info: serde_json::Value = info.json().await.unwrap();
    assert_eq!(info["status"], "active");
    assert!(info["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "write"));
    assert!(info["key_prefix"].as_str().unwrap().starts_with("iph_"));

    // 无效密钥 401
    let bad = app
        .client
        .get(app.url("/v1/key"))
        .bearer_auth("iph_invalid")
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 401);
    let bad: serde_json::Value = bad.json().await.unwrap();
    assert_eq!(bad["error"]["code"], "unauthorized");
}

async fn page_has_header(app: &TestApp, token: &str, header: &str) -> bool {
    let response = app
        .client
        .get(app.url(&format!("/v1/keys/verify?token={token}")))
        .send()
        .await
        .unwrap();
    response.headers().contains_key(header)
}

#[tokio::test]
async fn reset_revokes_old_key_and_failed_send_is_retryable() {
    let Some(app) = app().await else { return };

    let first = app.issue_key("owner@qq.com").await;
    assert_eq!(
        app.client
            .get(app.url("/v1/key"))
            .bearer_auth(&first)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // 重置流程：先绕过冷却（改库时间，不睡眠）
    app.backdate_verifications("owner@qq.com").await;
    let response = app
        .client
        .post(app.url("/v1/keys/request"))
        .json(&serde_json::json!({"email": "owner@qq.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 202);
    app.wait_mail_tasks().await;
    let mails = app.mailer.mails().await;
    let verify_mail = mails
        .iter()
        .rev()
        .find(|m| m.subject.contains("验证"))
        .unwrap();
    assert!(verify_mail.body.contains("重置"), "重置邮件措辞错误");

    let token = app.latest_verification_token().await;
    let page = app
        .client
        .get(app.url(&format!("/v1/keys/verify?token={token}")))
        .send()
        .await
        .unwrap();
    assert!(page.text().await.unwrap().contains("作废"));

    let confirm = app
        .client
        .post(app.url("/v1/keys/verify"))
        .form(&[("token", token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(confirm.status(), 200);
    let second = app.latest_api_key().await;
    assert_ne!(first, second);

    // 新密钥可用，旧密钥立即 401
    assert_eq!(
        app.client
            .get(app.url("/v1/key"))
            .bearer_auth(&second)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        app.client
            .get(app.url("/v1/key"))
            .bearer_auth(&first)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    // 发信失败：不产生有效密钥，链接可重试
    let response = app
        .client
        .post(app.url("/v1/keys/request"))
        .json(&serde_json::json!({"email": "retry@qq.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 202);
    let token = app.latest_verification_token().await;
    app.mailer.set_fail(true);
    let confirm = app
        .client
        .post(app.url("/v1/keys/verify"))
        .form(&[("token", token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(confirm.status(), 200);
    assert!(confirm.text().await.unwrap().contains("发送失败"));
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM api_keys WHERE email_hmac = $1 AND status = 'active'",
    )
    .bind(app.state.config.account_hmac("retry@qq.com"))
    .fetch_one(&app.state.pool)
    .await
    .unwrap();
    assert_eq!(active, 0, "发信失败时不应产生有效密钥");
    // 没有遗留的 pending 密钥（事务 C 已回滚）
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM api_keys WHERE email_hmac = $1 AND status = 'pending_delivery'",
    )
    .bind(app.state.config.account_hmac("retry@qq.com"))
    .fetch_one(&app.state.pool)
    .await
    .unwrap();
    assert_eq!(pending, 0, "发信失败后不应遗留 pending 密钥");

    app.mailer.set_fail(false);
    let confirm = app
        .client
        .post(app.url("/v1/keys/verify"))
        .form(&[("token", token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(confirm.status(), 200);
    assert!(confirm.text().await.unwrap().contains("密钥已发送到邮箱"));
    let retry_key = app.latest_api_key().await;
    assert_eq!(
        app.client
            .get(app.url("/v1/key"))
            .bearer_auth(&retry_key)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}

/// 同一邮箱两条链接并发确认，最终只有一把 active 密钥，且都不返回 500。
#[tokio::test]
async fn concurrent_confirm_of_two_links_keeps_single_active_key() {
    let Some(app) = app_with(|config| {
        config.rate_limits.key_verify_per_hour = 100;
    })
    .await
    else {
        return;
    };

    let email = "race@qq.com";
    // 拿两条有效链接
    for round in 0..2 {
        if round > 0 {
            app.backdate_verifications(email).await;
        }
        let response = app
            .client
            .post(app.url("/v1/keys/request"))
            .json(&serde_json::json!({"email": email}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 202);
    }
    app.wait_mail_tasks().await;
    let mails = app.mailer.mails().await;
    let tokens: Vec<String> = mails
        .iter()
        .filter(|m| m.subject.contains("验证") && m.to == email)
        .map(|m| {
            let marker = "/v1/keys/verify?token=";
            let start = m.body.find(marker).unwrap() + marker.len();
            m.body[start..]
                .split_whitespace()
                .next()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(tokens.len(), 2, "应有两条验证邮件");

    let (first, second) = (&tokens[0], &tokens[1]);
    let client = app.client.clone();
    let url1 = app.url("/v1/keys/verify");
    let url2 = app.url("/v1/keys/verify");
    let (a, b) = tokio::join!(
        async {
            client
                .post(&url1)
                .form(&[("token", first.as_str())])
                .send()
                .await
                .unwrap()
        },
        async {
            app.client
                .post(&url2)
                .form(&[("token", second.as_str())])
                .send()
                .await
                .unwrap()
        }
    );
    for (name, response) in [("first", a), ("second", b)] {
        assert_eq!(response.status(), 200, "{name} 不应返回 500");
    }

    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM api_keys WHERE email_hmac = $1 AND status = 'active'",
    )
    .bind(app.state.config.account_hmac(email))
    .fetch_one(&app.state.pool)
    .await
    .unwrap();
    assert_eq!(active, 1, "并发确认后只能有一把 active 密钥");
    // pending 也不应遗留
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM api_keys WHERE email_hmac = $1 AND status = 'pending_delivery'",
    )
    .bind(app.state.config.account_hmac(email))
    .fetch_one(&app.state.pool)
    .await
    .unwrap();
    assert_eq!(pending, 0);
}

/// 事务 B 只在 pending 密钥仍在时才生效；pending 密钥消失时整体回滚，
/// 用户当前有效的密钥不能被顺手吊销。
#[tokio::test]
async fn activation_is_all_or_nothing() {
    use image_prompt_hub::api::keys::activate_key;

    let Some(app) = app().await else { return };
    let pool = &app.state.pool;
    let email = "activate@qq.com";
    let email_hmac = app.state.config.account_hmac(email);

    // 账号已有一把有效密钥
    let current = app.create_key_direct(email, &["read", "write"]).await;
    let insert_pending = || async {
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO api_keys (id, key_prefix, key_hash, email_hmac, status)
             VALUES ($1, 'iph_pend', $2, $3, 'pending_delivery')",
        )
        .bind(id)
        .bind(format!("hash-{id}"))
        .bind(&email_hmac)
        .execute(pool)
        .await
        .unwrap();
        id
    };
    let insert_verification = || async {
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO email_verifications
               (id, token_hash, email_hmac, email_ciphertext, purpose, expires_at, ip_hash, used_at)
             VALUES ($1, $2, $3, '\\x0102'::bytea, 'reset', now() + interval '30 minutes', 'ip', now())",
        )
        .bind(id)
        .bind(format!("token-{id}"))
        .bind(&email_hmac)
        .execute(pool)
        .await
        .unwrap();
        id
    };
    let status_of = |id: uuid::Uuid| async move {
        sqlx::query_scalar::<_, String>("SELECT status FROM api_keys WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .unwrap()
    };

    // pending 密钥已被清理任务删掉：返回 false，旧密钥原样有效，密文不清空
    let vanished = insert_pending().await;
    let verification = insert_verification().await;
    sqlx::query("DELETE FROM api_keys WHERE id = $1")
        .bind(vanished)
        .execute(pool)
        .await
        .unwrap();
    assert!(!activate_key(pool, &email_hmac, vanished, verification)
        .await
        .unwrap());
    assert_eq!(app.count_keys(email, "active").await, 1);
    assert_eq!(
        app.client
            .get(app.url("/v1/key"))
            .bearer_auth(&current)
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "激活失败不能吊销当前有效的密钥"
    );
    let ciphertext_len: i32 = sqlx::query_scalar(
        "SELECT length(email_ciphertext) FROM email_verifications WHERE id = $1",
    )
    .bind(verification)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(ciphertext_len, 2, "激活失败时不应清空邮箱密文");

    // 正常激活：旧密钥被吊销、新密钥生效、密文清空
    let pending = insert_pending().await;
    assert!(activate_key(pool, &email_hmac, pending, verification)
        .await
        .unwrap());
    assert_eq!(status_of(pending).await.as_deref(), Some("active"));
    assert_eq!(app.count_keys(email, "active").await, 1);
    assert_eq!(app.count_keys(email, "revoked").await, 1);
    let ciphertext_len: i32 = sqlx::query_scalar(
        "SELECT length(email_ciphertext) FROM email_verifications WHERE id = $1",
    )
    .bind(verification)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(ciphertext_len, 0);
}

#[tokio::test]
async fn request_response_identical_for_existing_and_new_email() {
    let Some(app) = app_with(|config| {
        config.rate_limits.key_request_per_hour = 100;
    })
    .await
    else {
        return;
    };

    let existing_body = {
        let response = app
            .client
            .post(app.url("/v1/keys/request"))
            .json(&serde_json::json!({"email": "known@qq.com"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 202);
        // 变成“已有密钥”再取一次响应
        app.backdate_verifications("known@qq.com").await;
        app.issue_key("known@qq.com").await;
        app.backdate_verifications("known@qq.com").await;
        let again = app
            .client
            .post(app.url("/v1/keys/request"))
            .json(&serde_json::json!({"email": "known@qq.com"}))
            .send()
            .await
            .unwrap();
        assert_eq!(again.status(), 202);
        again.text().await.unwrap()
    };

    let unknown = app
        .client
        .post(app.url("/v1/keys/request"))
        .json(&serde_json::json!({"email": "fresh@qq.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 202);
    let unknown_text = unknown.text().await.unwrap();
    assert_eq!(
        existing_body, unknown_text,
        "有无密钥的邮箱返回必须完全一致"
    );

    // 不在白名单 → email_not_allowed
    let denied = app
        .client
        .post(app.url("/v1/keys/request"))
        .json(&serde_json::json!({"email": "a@outlook.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 400);
    let denied: serde_json::Value = denied.json().await.unwrap();
    assert_eq!(denied["error"]["code"], "email_not_allowed");

    // 身份规范化：gmail 变体与原地址是同一账号（issue_key 自带一次申请，冷却内不能再申请）
    app.issue_key("base@gmail.com").await;
    app.backdate_verifications("base@gmail.com").await;
    let variant = app
        .client
        .post(app.url("/v1/keys/request"))
        .json(&serde_json::json!({"email": "b.ase+tag@gmail.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(variant.status(), 202);
    app.wait_mail_tasks().await;
    let mails = app.mailer.mails().await;
    let verify = mails
        .iter()
        .rev()
        .find(|m| m.subject.contains("验证"))
        .unwrap();
    assert!(
        verify.body.contains("重置"),
        "同身份的 gmail 变体应按重置处理"
    );
}

/// 同一邮箱的验证邮件冷却：冷却内再申请得到 429 和 Retry-After，改库时间越过冷却后恢复。
#[tokio::test]
async fn email_cooldown_blocks_repeat_requests_until_it_expires() {
    let Some(app) = app().await else { return };

    assert_eq!(app.request_key("limit@qq.com").await.status(), 202);
    let second = app.request_key("limit@qq.com").await;
    assert_eq!(second.status(), 429);
    let retry_after: u64 = second.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (1..=600).contains(&retry_after),
        "Retry-After 应是冷却剩余秒数：{retry_after}"
    );
    // 其他邮箱不受影响
    assert_eq!(app.request_key("other-limit@qq.com").await.status(), 202);

    app.backdate_verifications("limit@qq.com").await;
    assert_eq!(app.request_key("limit@qq.com").await.status(), 202);
}

/// 每日上限按“今天”的日历日统计。
///
/// 被统计的记录必须属于今天，又要早于冷却窗口，所以这里把冷却缩到最短，
/// 并把记录时间放到今天零点，不用“往前推若干小时”——那样在 UTC 零点后的头几个小时里
/// 会把记录推到昨天，测试结果就取决于运行时刻。
#[tokio::test]
async fn daily_limit_counts_requests_made_today() {
    let Some(app) = app_with(|config| {
        config.email_cooldown_secs = 1;
        config.email_per_day_limit = 2;
    })
    .await
    else {
        return;
    };

    // 只有午夜后的头几秒里造不出“早于冷却的今天的记录”，等它过去
    let since_midnight: f64 =
        sqlx::query_scalar("SELECT extract(epoch FROM now() - date_trunc('day', now()))::float8")
            .fetch_one(&app.state.pool)
            .await
            .unwrap();
    if since_midnight < 5.0 {
        tokio::time::sleep(std::time::Duration::from_secs_f64(5.0 - since_midnight)).await;
    }
    let age_into_today = || async {
        sqlx::query("UPDATE email_verifications SET created_at = date_trunc('day', now())")
            .execute(&app.state.pool)
            .await
            .unwrap();
    };

    assert_eq!(app.request_key("daily@qq.com").await.status(), 202);
    age_into_today().await;
    assert_eq!(app.request_key("daily@qq.com").await.status(), 202);
    age_into_today().await;
    let third = app.request_key("daily@qq.com").await;
    assert_eq!(third.status(), 429, "今天已申请 2 次，第 3 次应撞每日上限");
    assert!(third.headers().contains_key("retry-after"));

    // 昨天的记录不计入今天
    sqlx::query("UPDATE email_verifications SET created_at = date_trunc('day', now()) - interval '1 second'")
        .execute(&app.state.pool)
        .await
        .unwrap();
    assert_eq!(app.request_key("daily@qq.com").await.status(), 202);
    // 其他邮箱不受影响
    assert_eq!(app.request_key("daily-other@qq.com").await.status(), 202);
}

/// 令牌过期、重复使用都被拒绝（过期时间直接改库，不睡眠）。
#[tokio::test]
async fn expired_and_reused_tokens_are_rejected() {
    let Some(app) = app().await else { return };

    // 令牌过期
    assert_eq!(app.request_key("expire@qq.com").await.status(), 202);
    let token = app.latest_verification_token().await;
    sqlx::query("UPDATE email_verifications SET expires_at = now() - interval '1 hour'")
        .execute(&app.state.pool)
        .await
        .unwrap();
    let page = app
        .client
        .get(app.url(&format!("/v1/keys/verify?token={token}")))
        .send()
        .await
        .unwrap();
    assert!(page.text().await.unwrap().contains("链接无效"));
    let confirm = app.confirm_token(&token).await;
    assert!(confirm.text().await.unwrap().contains("链接无效"));
    assert_eq!(app.count_keys("expire@qq.com", "active").await, 0);

    // 令牌重复使用
    assert_eq!(app.request_key("reuse@qq.com").await.status(), 202);
    let token = app.latest_verification_token().await;
    let confirm = app.confirm_token(&token).await;
    assert!(confirm.text().await.unwrap().contains("密钥已发送到邮箱"));
    let confirm = app.confirm_token(&token).await;
    assert!(confirm.text().await.unwrap().contains("链接无效"));
    assert_eq!(app.count_keys("reuse@qq.com", "active").await, 1);
}

fn template_json(name: &str, content: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "ai_description": "给模型的说明",
        "content": content,
        "defaults": {"resolution": "2K"},
        "reference": "optional",
        "tags": ["测试", name],
        "author": "tester",
    })
}

#[tokio::test]
async fn write_endpoints_and_permissions() {
    let Some(app) = app().await else { return };
    let owner_key = app
        .create_key_direct("writer@qq.com", &["read", "write"])
        .await;
    let other_key = app
        .create_key_direct("other@qq.com", &["read", "write"])
        .await;
    let admin_key = app
        .create_key_direct("boss@qq.com", &["read", "write", "admin"])
        .await;

    // 匿名写被拒
    assert_eq!(
        app.client
            .post(app.url("/v1/templates"))
            .json(&template_json("匿名", "内容"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    // read-only 权限被拒
    let read_only = app.create_key_direct("reader@qq.com", &["read"]).await;
    assert_eq!(
        app.client
            .post(app.url("/v1/templates"))
            .bearer_auth(&read_only)
            .json(&template_json("只读", "内容"))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    // 上传
    let created = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&owner_key)
        .json(&template_json(
            "赛博朋克城市",
            "赛博朋克风格的城市 {{input}}",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created: serde_json::Value = created.json().await.unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["version"], 1);
    assert_eq!(created["tags"].as_array().unwrap().len(), 2);

    // 导入部分成功
    let import_body = serde_json::json!({
        "format": "gemini-image-templates",
        "version": 1,
        "updated_at": "2026-01-01T00:00:00Z",
        "templates": [
            template_json("导入甲", "甲的内容 {{input}}"),
            {"name": "非法占位符", "content": "{{oops}} 内容", "id": "ignored"},
            template_json("导入乙", "乙的内容 {{input}}"),
        ]
    });
    let imported = app
        .client
        .post(app.url("/v1/templates/import"))
        .bearer_auth(&owner_key)
        .json(&import_body)
        .send()
        .await
        .unwrap();
    assert_eq!(imported.status(), 200);
    let imported: serde_json::Value = imported.json().await.unwrap();
    let results = imported["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert!(results[0].get("id").is_some());
    assert!(results[1].get("error").is_some());
    assert!(results[2].get("id").is_some());

    // 修改：If-Match 不匹配 409
    let wrong = app
        .client
        .put(app.url(&format!("/v1/templates/{id}")))
        .bearer_auth(&owner_key)
        .header("If-Match", "\"wrong-v9\"")
        .json(&template_json("改名", "新内容 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 409);
    // 非本人修改 403
    let forbidden = app
        .client
        .put(app.url(&format!("/v1/templates/{id}")))
        .bearer_auth(&other_key)
        .json(&template_json("越权", "内容 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(forbidden.status(), 403);
    // 本人修改成功，版本加 1
    let updated = app
        .client
        .put(app.url(&format!("/v1/templates/{id}")))
        .bearer_auth(&owner_key)
        .header("If-Match", format!("\"{id}-v1\""))
        .json(&template_json("改名", "新内容 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(updated.status(), 200);
    let updated: serde_json::Value = updated.json().await.unwrap();
    assert_eq!(updated["version"], 2);
    // admin 可改任何模板
    let admin_update = app
        .client
        .put(app.url(&format!("/v1/templates/{id}")))
        .bearer_auth(&admin_key)
        .json(&template_json("管理员改", "内容 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(admin_update.status(), 200);

    // 非本人删除 403，本人删除 204
    assert_eq!(
        app.client
            .delete(app.url(&format!("/v1/templates/{id}")))
            .bearer_auth(&other_key)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        app.client
            .delete(app.url(&format!("/v1/templates/{id}")))
            .bearer_auth(&owner_key)
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        app.client
            .get(app.url(&format!("/v1/templates/{id}")))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // me/templates 不含 deleted
    let mine = app
        .client
        .get(app.url("/v1/me/templates"))
        .bearer_auth(&owner_key)
        .send()
        .await
        .unwrap();
    assert_eq!(mine.status(), 200);
    let mine: serde_json::Value = mine.json().await.unwrap();
    let statuses: Vec<&str> = mine["templates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["status"].as_str().unwrap())
        .collect();
    assert!(
        statuses.iter().all(|s| *s != "deleted"),
        "me 列表不应含 deleted"
    );
}

const SOURCE_URL: &str = "https://ai.google.dev/gemini-api/docs/image-generation";

/// GET 并解析 JSON，状态码必须是 200。
async fn get_json(app: &TestApp, path: &str, key: Option<&str>) -> serde_json::Value {
    let mut request = app.client.get(app.url(path));
    if let Some(key) = key {
        request = request.bearer_auth(key);
    }
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), 200, "{path}");
    response.json().await.unwrap()
}

/// 取目录快照并解压成 JSON 包。
async fn fetch_catalog_package(app: &TestApp) -> serde_json::Value {
    let response = app
        .client
        .get(app.url("/v1/catalog"))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let raw = response.bytes().await.unwrap();
    let mut plain = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&raw[..]), &mut plain).unwrap();
    serde_json::from_slice(&plain).unwrap()
}

/// 在模板数组里按 id 找一条。
fn find_template<'a>(templates: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    templates
        .as_array()
        .expect("templates 应是数组")
        .iter()
        .find(|template| template["id"] == id)
        .unwrap_or_else(|| panic!("结果里没有 {id}：{templates}"))
}

/// `Some` 时 source_url 等于给定值；`None` 时连这个键都不存在（而不是 null）。
fn assert_source_url(template: &serde_json::Value, expected: Option<&str>, place: &str) {
    match expected {
        Some(url) => assert_eq!(template["source_url"], url, "{place}"),
        None => assert!(
            template.get("source_url").is_none(),
            "{place} 不应出现 source_url 键：{template}"
        ),
    }
}

async fn stored_source_url(app: &TestApp, id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT source_url FROM templates WHERE id = $1")
        .bind(id)
        .fetch_one(&app.state.pool)
        .await
        .unwrap()
}

/// 带出处的模板以规范化后的值出现在每条读取路径上；不带时响应里没有这个键。
#[tokio::test]
async fn source_url_is_stored_normalized_and_shown_on_every_read_path() {
    let Some(app) = app().await else { return };
    let key = app
        .create_key_direct("source-url@qq.com", &["read", "write"])
        .await;

    // 大写主机名与两端空白在保存前被规范化
    let mut with_source = template_json("赛博朋克", "赛博朋克风格的城市 {{input}}");
    with_source["source_url"] =
        serde_json::json!("  https://AI.Google.DEV/gemini-api/docs/image-generation  ");
    let created = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&with_source)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created: serde_json::Value = created.json().await.unwrap();
    assert_source_url(&created, Some(SOURCE_URL), "创建响应");
    let with_id = created["id"].as_str().unwrap().to_string();

    let created = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&template_json("水墨山水", "水墨山水画 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created: serde_json::Value = created.json().await.unwrap();
    assert_source_url(&created, None, "不带出处的创建响应");
    let without_id = created["id"].as_str().unwrap().to_string();

    assert_eq!(
        stored_source_url(&app, &with_id).await.as_deref(),
        Some(SOURCE_URL),
        "库里存的是规范化后的值"
    );
    assert_eq!(stored_source_url(&app, &without_id).await, None);

    app.wait_search("赛博朋克", &with_id, true).await;
    app.wait_search("水墨山水", &without_id, true).await;
    app.wait_catalog_count(2).await;

    // 检索路径：每条命中各自带或不带这个键
    let searched = get_json(&app, "/v1/templates?q=赛博朋克", None).await;
    assert_source_url(
        find_template(&searched["templates"], &with_id),
        Some(SOURCE_URL),
        "检索",
    );
    let searched = get_json(&app, "/v1/templates?q=水墨山水", None).await;
    assert_source_url(
        find_template(&searched["templates"], &without_id),
        None,
        "检索",
    );

    let detail = get_json(&app, &format!("/v1/templates/{with_id}"), None).await;
    assert_source_url(&detail, Some(SOURCE_URL), "详情");
    let detail = get_json(&app, &format!("/v1/templates/{without_id}"), None).await;
    assert_source_url(&detail, None, "不带出处的详情");

    let list = get_json(&app, "/v1/templates", None).await;
    let by_tag = get_json(&app, "/v1/templates?tag=测试", None).await;
    let batch = get_json(
        &app,
        &format!("/v1/templates/batch?ids={with_id},{without_id}"),
        None,
    )
    .await;
    let mine = get_json(&app, "/v1/me/templates", Some(&key)).await;
    let catalog = fetch_catalog_package(&app).await;
    for (place, templates) in [
        ("列表", &list["templates"]),
        ("按标签列表", &by_tag["templates"]),
        ("批量", &batch["templates"]),
        ("我的模板", &mine["templates"]),
        ("目录快照", &catalog["templates"]),
    ] {
        assert_eq!(templates.as_array().unwrap().len(), 2, "{place}");
        assert_source_url(find_template(templates, &with_id), Some(SOURCE_URL), place);
        assert_source_url(find_template(templates, &without_id), None, place);
    }

    // OpenAPI 的字段说明里能看到新字段
    let openapi = get_json(&app, "/openapi.json", None).await;
    for schema in ["TemplateJson", "TemplateUpsertDoc"] {
        let property = &openapi["components"]["schemas"][schema]["properties"]["source_url"];
        assert!(property.is_object(), "{schema} 缺少 source_url：{openapi}");
        assert!(
            property["description"]
                .as_str()
                .unwrap_or("")
                .contains("出处"),
            "{schema}.source_url 缺少说明：{property}"
        );
    }
}

/// 修改按整体替换处理：带新值就更新，不带就清空；非法值一律 400，且不改动已有数据。
#[tokio::test]
async fn source_url_update_replaces_and_invalid_values_are_rejected() {
    let Some(app) = app().await else { return };
    let key = app
        .create_key_direct("source-url-edit@qq.com", &["read", "write"])
        .await;

    let mut body = template_json("出处修改", "原始内容 {{input}}");
    body["source_url"] = serde_json::json!("https://example.com/original");
    let created = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created: serde_json::Value = created.json().await.unwrap();
    assert_source_url(&created, Some("https://example.com/original"), "创建响应");
    assert_eq!(created["version"], 1);
    let id = created["id"].as_str().unwrap().to_string();
    let template_url = app.url(&format!("/v1/templates/{id}"));

    // PUT 带新值：更新并规范化，version 加 1
    let mut body = template_json("出处修改", "第二版内容 {{input}}");
    body["source_url"] = serde_json::json!("https://Example.ORG/license");
    let updated = app
        .client
        .put(&template_url)
        .bearer_auth(&key)
        .header("If-Match", format!("\"{id}-v1\""))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(updated.status(), 200);
    let updated: serde_json::Value = updated.json().await.unwrap();
    assert_eq!(updated["version"], 2);
    assert_source_url(&updated, Some("https://example.org/license"), "更新响应");
    let detail = get_json(&app, &format!("/v1/templates/{id}"), None).await;
    assert_source_url(&detail, Some("https://example.org/license"), "更新后的详情");
    assert_eq!(detail["version"], 2);

    // 非法值：POST 与 PUT 都是 400，错误信息指出字段
    let too_long = format!("https://example.com/{}", "a".repeat(281));
    for bad in [
        "http://example.com/",
        "javascript:alert(1)",
        "https://localhost/",
        "https://127.0.0.1/",
        "https://user:pw@example.com/",
        "https://example.com/a b",
        too_long.as_str(),
    ] {
        let mut body = template_json("非法出处", "内容 {{input}}");
        body["source_url"] = serde_json::json!(bad);
        for request in [
            app.client.post(app.url("/v1/templates")),
            app.client.put(&template_url),
        ] {
            let response = request.bearer_auth(&key).json(&body).send().await.unwrap();
            assert_eq!(response.status(), 400, "{bad}");
            let response: serde_json::Value = response.json().await.unwrap();
            assert!(
                response["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("source_url"),
                "错误信息应指出字段：{response}"
            );
        }
    }
    // 被拒绝的请求没有改动任何数据：没有新增模板，已有模板仍是第 2 版
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM templates")
        .fetch_one(&app.state.pool)
        .await
        .unwrap();
    assert_eq!(total, 1);
    let detail = get_json(&app, &format!("/v1/templates/{id}"), None).await;
    assert_eq!(detail["version"], 2);
    assert_source_url(
        &detail,
        Some("https://example.org/license"),
        "被拒绝后的详情",
    );

    // PUT 不带 source_url：清空，version 再加 1
    let cleared = app
        .client
        .put(&template_url)
        .bearer_auth(&key)
        .json(&template_json("出处修改", "第三版内容 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(cleared.status(), 200);
    let cleared: serde_json::Value = cleared.json().await.unwrap();
    assert_eq!(cleared["version"], 3);
    assert_source_url(&cleared, None, "清空后的更新响应");
    let detail = get_json(&app, &format!("/v1/templates/{id}"), None).await;
    assert_source_url(&detail, None, "清空后的详情");
    assert_eq!(stored_source_url(&app, &id).await, None);

    // 空串同样视为未提供
    let mut body = template_json("出处修改", "第四版内容 {{input}}");
    body["source_url"] = serde_json::json!("   ");
    let blank = app
        .client
        .put(&template_url)
        .bearer_auth(&key)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(blank.status(), 200);
    let blank: serde_json::Value = blank.json().await.unwrap();
    assert_eq!(blank["version"], 4);
    assert_source_url(&blank, None, "空白值的更新响应");
}

/// 导入包里的 source_url 照常保存；某一条的值非法只让该条失败。
#[tokio::test]
async fn import_keeps_source_url_and_isolates_invalid_items() {
    let Some(app) = app().await else { return };
    let key = app
        .create_key_direct("source-url-import@qq.com", &["read", "write"])
        .await;

    let mut with_source = template_json("导入带出处", "带出处的内容 {{input}}");
    with_source["source_url"] =
        serde_json::json!("https://AI.Google.DEV/gemini-api/docs/image-generation");
    let mut bad_source = template_json("导入坏出处", "出处非法的内容 {{input}}");
    bad_source["source_url"] = serde_json::json!("http://example.com/");
    let response = app
        .client
        .post(app.url("/v1/templates/import"))
        .bearer_auth(&key)
        .json(&serde_json::json!({
            "format": "gemini-image-templates",
            "version": 1,
            "templates": [
                with_source,
                bad_source,
                template_json("导入无出处", "没有出处的内容 {{input}}"),
            ],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: serde_json::Value = response.json().await.unwrap();
    let results = result["results"].as_array().unwrap();
    assert_eq!(results.len(), 3, "{result}");
    assert!(results[1].get("id").is_none(), "{result}");
    assert!(
        results[1]["error"].as_str().unwrap().contains("source_url"),
        "错误信息应指出字段：{result}"
    );

    let first = results[0]["id"].as_str().expect("第一条应导入成功");
    let third = results[2]["id"].as_str().expect("第三条应导入成功");
    let detail = get_json(&app, &format!("/v1/templates/{first}"), None).await;
    assert_source_url(&detail, Some(SOURCE_URL), "导入后的详情");
    let detail = get_json(&app, &format!("/v1/templates/{third}"), None).await;
    assert_source_url(&detail, None, "不带出处的导入详情");
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM templates")
        .fetch_one(&app.state.pool)
        .await
        .unwrap();
    assert_eq!(total, 2, "非法的那一条不应入库");
}

/// 走真实的邮箱重置流程，重置后旧密钥失效，新密钥仍能修改、删除并在“我的模板”里看到。
#[tokio::test]
async fn ownership_survives_key_reset() {
    let Some(app) = app().await else { return };
    let email = "stable@qq.com";
    let old_key = app.issue_key(email).await;

    let created = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&old_key)
        .json(&template_json("归属测试", "归属测试内容 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created: serde_json::Value = created.json().await.unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    let other_id = {
        let second = app
            .client
            .post(app.url("/v1/templates"))
            .bearer_auth(&old_key)
            .json(&template_json("归属测试二", "另一个模板 {{input}}"))
            .send()
            .await
            .unwrap();
        let second: serde_json::Value = second.json().await.unwrap();
        second["id"].as_str().unwrap().to_string()
    };

    // 邮箱重置：密钥换了，owner_key_id 仍是旧密钥，归属必须按账号身份判断
    app.backdate_verifications(email).await;
    let new_key = app.issue_key(email).await;
    assert_ne!(old_key, new_key);
    assert_eq!(app.count_keys(email, "active").await, 1);
    assert_eq!(
        app.client
            .get(app.url("/v1/key"))
            .bearer_auth(&old_key)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let recorded_key: uuid::Uuid =
        sqlx::query_scalar("SELECT owner_key_id FROM templates WHERE id = $1")
            .bind(&id)
            .fetch_one(&app.state.pool)
            .await
            .unwrap();
    let new_key_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM api_keys WHERE email_hmac = $1 AND status = 'active'")
            .bind(app.state.config.account_hmac(email))
            .fetch_one(&app.state.pool)
            .await
            .unwrap();
    assert_ne!(
        recorded_key, new_key_id,
        "owner_key_id 只记录上传时用的密钥"
    );

    // 新密钥能看到“我的模板”
    let mine = app
        .client
        .get(app.url("/v1/me/templates"))
        .bearer_auth(&new_key)
        .send()
        .await
        .unwrap();
    assert_eq!(mine.status(), 200);
    let mine: serde_json::Value = mine.json().await.unwrap();
    assert_eq!(mine["templates"].as_array().unwrap().len(), 2);

    // 新密钥能修改、能删除
    let updated = app
        .client
        .put(app.url(&format!("/v1/templates/{id}")))
        .bearer_auth(&new_key)
        .json(&template_json("归属改名", "新内容 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(updated.status(), 200);
    assert_eq!(
        app.client
            .delete(app.url(&format!("/v1/templates/{id}")))
            .bearer_auth(&new_key)
            .send()
            .await
            .unwrap()
            .status(),
        204
    );

    // 其他账号仍然不能动它
    let stranger = app
        .create_key_direct("stranger@qq.com", &["read", "write"])
        .await;
    assert_eq!(
        app.client
            .delete(app.url(&format!("/v1/templates/{other_id}")))
            .bearer_auth(&stranger)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
}

/// 账号每小时新建额度与总数上限。
#[tokio::test]
async fn account_create_quota_and_template_limit() {
    let Some(app) = app_with(|config| {
        config.account_create_per_hour = 2;
        config.account_template_limit = 3;
    })
    .await
    else {
        return;
    };
    let key = app
        .create_key_direct("quota@qq.com", &["read", "write"])
        .await;

    // 每小时新建 2 条：前两条成功，第三条 429
    for i in 1..=2 {
        let response = app
            .client
            .post(app.url("/v1/templates"))
            .bearer_auth(&key)
            .json(&template_json(&format!("额度{i}"), "内容 {{input}}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201, "第 {i} 条应成功");
    }
    let blocked = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&template_json("额度3", "内容 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), 429);
    let blocked_response_headers = blocked.headers().clone();
    let blocked: serde_json::Value = blocked.json().await.unwrap();
    assert!(
        blocked["error"]["message"]
            .as_str()
            .unwrap()
            .contains("每小时"),
        "错误信息应说明是哪一项：{blocked}"
    );

    // Retry-After 是窗口内最早一条创建满一小时的剩余秒数，而不是固定值
    let retry_after = |headers: &reqwest::header::HeaderMap| -> u64 {
        headers["retry-after"].to_str().unwrap().parse().unwrap()
    };
    assert!(
        (3500..=3600).contains(&retry_after(&blocked_response_headers)),
        "刚创建的模板应接近整整一小时后才释放名额"
    );
    sqlx::query("UPDATE templates SET created_at = now() - interval '59 minutes' WHERE owner_email_hmac = $1")
        .bind(app.state.config.account_hmac("quota@qq.com"))
        .execute(&app.state.pool)
        .await
        .unwrap();
    let nearly_free = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&template_json("额度3", "内容 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(nearly_free.status(), 429);
    assert!(
        (1..=120).contains(&retry_after(nearly_free.headers())),
        "59 分钟前创建的模板约一分钟后释放名额：{}",
        retry_after(nearly_free.headers())
    );

    // 把已建的改到一小时前，绕过新建额度，验证总数上限 3 → 403
    sqlx::query("UPDATE templates SET created_at = created_at - interval '2 hours' WHERE owner_email_hmac = $1")
        .bind(app.state.config.account_hmac("quota@qq.com"))
        .execute(&app.state.pool)
        .await
        .unwrap();
    let fourth = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&template_json("总数1", "内容 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(fourth.status(), 201);
    let fifth = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&template_json("总数2", "内容 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(fifth.status(), 403);
    let fifth: serde_json::Value = fifth.json().await.unwrap();
    assert!(
        fifth["error"]["message"].as_str().unwrap().contains("总数"),
        "错误信息应说明是哪一项：{fifth}"
    );
}

/// 导入时逐条计入新建额度，超出部分逐条报错。
#[tokio::test]
async fn import_counts_each_item_against_quota() {
    let Some(app) = app_with(|config| {
        config.account_create_per_hour = 2;
    })
    .await
    else {
        return;
    };
    let key = app
        .create_key_direct("import-quota@qq.com", &["read", "write"])
        .await;

    let templates: Vec<serde_json::Value> = (0..4)
        .map(|i| template_json(&format!("导入额度{i}"), "内容 {{input}}"))
        .collect();
    let response = app
        .client
        .post(app.url("/v1/templates/import"))
        .bearer_auth(&key)
        .json(&serde_json::json!({
            "format": "gemini-image-templates",
            "version": 1,
            "templates": templates,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: serde_json::Value = response.json().await.unwrap();
    let results = result["results"].as_array().unwrap();
    let ok_count = results.iter().filter(|r| r.get("id").is_some()).count();
    let quota_errors = results.iter().filter(|r| r.get("error").is_some()).count();
    assert_eq!(ok_count, 2, "只应成功 2 条：{result}");
    assert_eq!(quota_errors, 2);
    for item in results.iter().filter(|r| r.get("error").is_some()) {
        assert!(item["error"].as_str().unwrap().contains("每小时"));
    }
}

/// 封禁、解封与隐藏模板。
#[tokio::test]
async fn ban_and_unban_account() {
    let Some(app) = app().await else { return };
    let user_key = app
        .create_key_direct("banned@qq.com", &["read", "write"])
        .await;
    let admin_key = app
        .create_key_direct("ban-admin@qq.com", &["read", "write", "admin"])
        .await;

    let created = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&user_key)
        .json(&template_json("待封禁", "封禁前的模板 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created: serde_json::Value = created.json().await.unwrap();
    let template_id = created["id"].as_str().unwrap().to_string();

    // 先申请一条验证链接，封禁后确认应被拒
    assert_eq!(
        app.client
            .post(app.url("/v1/keys/request"))
            .json(&serde_json::json!({"email": "banned@qq.com"}))
            .send()
            .await
            .unwrap()
            .status(),
        202
    );
    let token = app.latest_verification_token().await;

    // 封禁：吊销密钥 + 隐藏模板
    let ban = app
        .client
        .post(app.url("/v1/admin/accounts/ban"))
        .bearer_auth(&admin_key)
        .json(&serde_json::json!({
            "email": "banned@qq.com",
            "reason": "测试封禁",
            "hide_templates": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(ban.status(), 200);
    let ban: serde_json::Value = ban.json().await.unwrap();
    assert_eq!(ban["revoked_keys"], 1);
    assert_eq!(ban["hidden_templates"], 1);

    // 密钥被吊销
    assert_eq!(
        app.client
            .get(app.url("/v1/key"))
            .bearer_auth(&user_key)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    // 模板被隐藏：详情 404、检索不出现、快照清空
    assert_eq!(
        app.client
            .get(app.url(&format!("/v1/templates/{template_id}")))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    app.wait_search("封禁前", &template_id, false).await;
    app.wait_catalog_count(0).await;

    // 被封禁邮箱申请：返回与普通邮箱完全相同的 202，但不发信
    let normal_body = {
        let response = app.request_key("normal@qq.com").await;
        assert_eq!(response.status(), 202);
        response.text().await.unwrap()
    };
    app.wait_mail_tasks().await;
    let mails_before = app.mailer.mails().await.len();
    app.backdate_verifications("banned@qq.com").await;
    let response = app.request_key("banned@qq.com").await;
    assert_eq!(response.status(), 202, "封禁邮箱的申请响应必须与其他一致");
    assert_eq!(
        response.text().await.unwrap(),
        normal_body,
        "响应正文也必须一致，不能暴露封禁状态"
    );
    assert_eq!(
        app.mailer.mails().await.len(),
        mails_before,
        "不应发出新邮件"
    );
    // 冷却对封禁邮箱同样生效：立即再申请得到与普通邮箱一样的 429，而不是又一个 202
    let again = app.request_key("banned@qq.com").await;
    assert_eq!(again.status(), 429, "冷却行为不能暴露封禁状态");
    assert!(again.headers().contains_key("retry-after"));
    let normal_again = app.request_key("normal@qq.com").await;
    assert_eq!(normal_again.status(), 429);
    assert_eq!(app.count_keys("banned@qq.com", "active").await, 0);

    // 封禁前拿到的链接确认时被拒
    let confirm = app
        .client
        .post(app.url("/v1/keys/verify"))
        .form(&[("token", token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(confirm.status(), 200);
    assert!(confirm.text().await.unwrap().contains("无法发放"));

    // 解封：不自动恢复模板，但可以重新申请
    let unban = app
        .client
        .post(app.url("/v1/admin/accounts/unban"))
        .bearer_auth(&admin_key)
        .json(&serde_json::json!({"email": "banned@qq.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unban.status(), 200);
    assert_eq!(
        app.client
            .get(app.url(&format!("/v1/templates/{template_id}")))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "解封不应自动恢复模板"
    );
    // 封禁期间登记的记录占用着冷却，改库时间后可以重新申请并拿到密钥
    app.backdate_verifications("banned@qq.com").await;
    let new_key = app.issue_key("banned@qq.com").await;
    assert!(new_key.starts_with("iph_"));
    assert_eq!(
        app.client
            .get(app.url("/v1/key"))
            .bearer_auth(&new_key)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}

/// 按密钥查账号（keys/lookup）。
#[tokio::test]
async fn admin_keys_lookup_by_key_id() {
    let Some(app) = app().await else { return };
    let user_key = app
        .create_key_direct("lookup@qq.com", &["read", "write"])
        .await;
    let admin_key = app
        .create_key_direct("lookup-admin@qq.com", &["read", "write", "admin"])
        .await;

    // 按邮箱查
    let by_email = app
        .client
        .post(app.url("/v1/admin/keys/lookup"))
        .bearer_auth(&admin_key)
        .json(&serde_json::json!({"email": "LOOKUP@qq.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(by_email.status(), 200);
    let by_email: serde_json::Value = by_email.json().await.unwrap();
    let key_id = by_email["keys"][0]["id"].as_str().unwrap().to_string();

    // 用 key_id 定位封禁（二选一定位）
    let ban = app
        .client
        .post(app.url("/v1/admin/accounts/ban"))
        .bearer_auth(&admin_key)
        .json(
            &serde_json::json!({"key_id": key_id, "reason": "按密钥封禁", "hide_templates": false}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(ban.status(), 200);
    assert_eq!(
        app.client
            .get(app.url("/v1/key"))
            .bearer_auth(&user_key)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
}

/// 无效密钥的连续 401 触发认证失败限流，429 带 Retry-After。
#[tokio::test]
async fn invalid_keys_trigger_auth_failure_rate_limit() {
    let Some(app) = app_with(|config| {
        config.rate_limits.auth_failure_per_min = 5;
    })
    .await
    else {
        return;
    };

    let mut got_429 = false;
    for i in 0..8 {
        let response = app
            .client
            .get(app.url("/v1/key"))
            .bearer_auth(format!("iph_invalid{i}"))
            .send()
            .await
            .unwrap();
        match response.status().as_u16() {
            401 => {}
            429 => {
                assert!(response.headers().contains_key("retry-after"));
                let body: serde_json::Value = response.json().await.unwrap();
                assert_eq!(body["error"]["code"], "rate_limited");
                got_429 = true;
                break;
            }
            other => panic!("意外状态码 {other}"),
        }
    }
    assert!(got_429, "大量无效密钥请求应触发 429");
}

/// 非法 CF-Connecting-IP 回退连接地址；合法的各 IP 独立计数。
#[tokio::test]
async fn invalid_cf_header_falls_back_to_socket_addr() {
    let Some(app) = app_with(|config| {
        config.trust_cf_connecting_ip = true;
        config.rate_limits.anon_read_per_min = 3;
        config.rate_limits.auth_failure_per_min = 1000;
    })
    .await
    else {
        return;
    };

    // 非法 CF 头：全部按连接地址 127.0.0.1 计数 → 第 4 次 429
    for _ in 0..3 {
        let response = app
            .client
            .get(app.url("/v1/status"))
            .header("cf-connecting-ip", "definitely-not-an-ip")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }
    let limited = app
        .client
        .get(app.url("/v1/status"))
        .header("cf-connecting-ip", "another-bogus")
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status(), 429, "非法头应回退连接地址共享限额");

    // 合法 CF 头：不同 IP 各自独立，不受上面 127.0.0.1 桶影响
    for ip in ["203.0.113.1", "203.0.113.2"] {
        let response = app
            .client
            .get(app.url("/v1/status"))
            .header("cf-connecting-ip", ip)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "合法头 {ip} 应有独立桶");
    }
}

/// 快照生成期间的改动最终会进快照；ETag 与正文始终来自同一次生成。
#[tokio::test]
async fn catalog_eventual_consistency_and_etag_body_pair() {
    let Some(app) = app_with(|config| {
        config.catalog_debounce_secs = 0;
    })
    .await
    else {
        return;
    };
    let key = app
        .create_key_direct("cat-race@qq.com", &["read", "write"])
        .await;

    // 连续快速上传 5 条（每条 mark_dirty 都可能落在上一次生成的窗口内）
    for i in 0..5 {
        let response = app
            .client
            .post(app.url("/v1/templates"))
            .bearer_auth(&key)
            .json(&template_json(&format!("快照{i}"), "内容 {{input}}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201);
    }
    app.wait_catalog_count(5).await;

    // ETag 与 gzip 正文必须来自同一次生成（同一 Arc）
    let version: serde_json::Value = app
        .client
        .get(app.url("/v1/catalog/version"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hash = version["hash"].as_str().unwrap().to_string();
    let catalog = app
        .client
        .get(app.url("/v1/catalog"))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    let etag = catalog
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(etag, format!("\"{hash}\""));
    let raw = catalog.bytes().await.unwrap();
    let mut decoder = flate2::read::GzDecoder::new(&raw[..]);
    let mut plain = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut plain).unwrap();
    assert_eq!(
        image_prompt_hub::crypto::sha256_hex(&plain),
        hash,
        "ETag 与正文必须一致"
    );

    // 删除后再看：最终一致
    let list = app
        .client
        .get(app.url("/v1/templates?limit=1"))
        .send()
        .await
        .unwrap();
    let list: serde_json::Value = list.json().await.unwrap();
    let first_id = list["templates"][0]["id"].as_str().unwrap().to_string();
    app.client
        .delete(app.url(&format!("/v1/templates/{first_id}")))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    app.wait_catalog_count(4).await;
}

/// 公开接口带 max-age，私有接口 no-store，带 Authorization 一律 private。
#[tokio::test]
async fn cache_control_policy() {
    let Some(app) = app().await else { return };
    let key = app.create_key_direct("cache@qq.com", &["read"]).await;

    let status = app.client.get(app.url("/v1/status")).send().await.unwrap();
    assert_eq!(
        status.headers().get("cache-control").unwrap(),
        "public, max-age=60",
        "公开状态接口应可缓存"
    );
    let catalog = app.client.get(app.url("/v1/catalog")).send().await.unwrap();
    assert_eq!(
        catalog.headers().get("cache-control").unwrap(),
        "public, max-age=300"
    );
    let version = app
        .client
        .get(app.url("/v1/catalog/version"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        version.headers().get("cache-control").unwrap(),
        "public, max-age=60"
    );
    let keyed = app
        .client
        .get(app.url("/v1/status"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(
        keyed.headers().get("cache-control").unwrap(),
        "private, no-store",
        "带密钥的请求一律私有"
    );
    let request_page = app
        .client
        .post(app.url("/v1/keys/request"))
        .json(&serde_json::json!({"email": "cache@qq.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        request_page.headers().get("cache-control").unwrap(),
        "no-store"
    );
}

/// 同一版本的并发修改只有一个成功，其余 409（所有请求都带同一个 If-Match，结果与交错顺序无关）。
#[tokio::test]
async fn concurrent_updates_of_same_version_only_one_wins() {
    let Some(app) = app().await else { return };
    let key = app
        .create_key_direct("concurrent@qq.com", &["read", "write"])
        .await;

    let created = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&template_json("并发修改", "原始内容 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created: serde_json::Value = created.json().await.unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    let url = app.url(&format!("/v1/templates/{id}"));
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..8 {
        let (client, url, key, etag) = (
            app.client.clone(),
            url.clone(),
            key.clone(),
            format!("\"{id}-v1\""),
        );
        tasks.spawn(async move {
            client
                .put(url)
                .bearer_auth(key)
                .header("If-Match", etag)
                .json(&template_json(
                    &format!("并发{i}"),
                    &format!("第 {i} 个内容 {{{{input}}}}"),
                ))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        });
    }
    let mut codes = Vec::new();
    while let Some(code) = tasks.join_next().await {
        codes.push(code.unwrap());
    }
    assert_eq!(
        codes.iter().filter(|c| **c == 200).count(),
        1,
        "同一版本只能有一个修改成功：{codes:?}"
    );
    assert_eq!(codes.iter().filter(|c| **c == 409).count(), 7, "{codes:?}");

    // 只涨了一个版本
    let detail: serde_json::Value = app
        .client
        .get(app.url(&format!("/v1/templates/{id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["version"], 2);
}

/// 数据库层的版本条件（确定性，不依赖请求交错）。
/// 两个修改都基于 v1 读出时，晚到的那个不能覆盖已经落库的修改。
#[tokio::test]
async fn stale_version_update_is_rejected_by_the_database_guard() {
    use image_prompt_hub::api::write::update_if_version;
    use image_prompt_hub::validate::{validate_upsert, TemplateUpsert};

    let Some(app) = app().await else { return };
    let key = app
        .create_key_direct("stale@qq.com", &["read", "write"])
        .await;
    let created = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&template_json("版本条件", "原始内容 {{input}}"))
        .send()
        .await
        .unwrap();
    let created: serde_json::Value = created.json().await.unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    let validated = |content: &str| {
        validate_upsert(&TemplateUpsert {
            name: Some("版本条件".into()),
            ai_description: None,
            content: Some(content.into()),
            defaults: None,
            reference: None,
            tags: None,
            author: None,
            source_url: None,
            nsfw: None,
        })
        .unwrap()
    };
    let pool = &app.state.pool;

    let first = update_if_version(pool, &id, &validated("先到的修改"), 1)
        .await
        .unwrap()
        .expect("基于当前版本的修改应成功");
    assert_eq!(first.version, 2);

    let late = update_if_version(pool, &id, &validated("晚到的修改"), 1)
        .await
        .unwrap();
    assert!(late.is_none(), "基于旧版本的修改不能落库");
    let content: String = sqlx::query_scalar("SELECT content FROM templates WHERE id = $1")
        .bind(&id)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(content, "先到的修改", "晚到的修改不能覆盖先到的");

    // 已删除的模板同样不会被修改
    sqlx::query("UPDATE templates SET status = 'deleted' WHERE id = $1")
        .bind(&id)
        .execute(pool)
        .await
        .unwrap();
    assert!(update_if_version(pool, &id, &validated("删除后"), 2)
        .await
        .unwrap()
        .is_none());
}

/// 额度检查与写入是原子的，同一账号的并发新建不会一起越过额度。
#[tokio::test]
async fn concurrent_creates_cannot_exceed_account_quota() {
    for (create_per_hour, total_limit, expected_status) in [(3u32, 1000u32, 429u16), (1000, 2, 403)]
    {
        let Some(app) = app_with(|config| {
            config.account_create_per_hour = create_per_hour;
            config.account_template_limit = total_limit;
        })
        .await
        else {
            return;
        };
        let key = app
            .create_key_direct("burst@qq.com", &["read", "write"])
            .await;
        let allowed = create_per_hour.min(total_limit) as usize;

        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..10 {
            let (client, url, key) = (app.client.clone(), app.url("/v1/templates"), key.clone());
            tasks.spawn(async move {
                client
                    .post(url)
                    .bearer_auth(key)
                    .json(&template_json(&format!("并发新建{i}"), "内容 {{input}}"))
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .as_u16()
            });
        }
        let mut codes = Vec::new();
        while let Some(code) = tasks.join_next().await {
            codes.push(code.unwrap());
        }
        assert_eq!(
            codes.iter().filter(|c| **c == 201).count(),
            allowed,
            "成功条数必须正好等于额度：{codes:?}"
        );
        assert_eq!(
            codes.iter().filter(|c| **c == expected_status).count(),
            10 - allowed,
            "{codes:?}"
        );
        let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM templates")
            .fetch_one(&app.state.pool)
            .await
            .unwrap();
        assert_eq!(stored as usize, allowed);
    }
}

/// 新建时 ID 撞主键就换 ID 重试，最多 3 次。
#[tokio::test]
async fn template_id_collision_retries_then_gives_up() {
    use image_prompt_hub::api::write::{create_template_row, CreateOutcome};
    use image_prompt_hub::validate::{validate_upsert, TemplateUpsert};

    let Some(app) = app().await else { return };
    let key = app
        .create_key_direct("collide@qq.com", &["read", "write"])
        .await;
    let created = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&template_json("占位", "已占用的 ID {{input}}"))
        .send()
        .await
        .unwrap();
    let created: serde_json::Value = created.json().await.unwrap();
    let taken = created["id"].as_str().unwrap().to_string();

    let owner =
        image_prompt_hub::auth::authenticate(&app.state.pool, &app.state.config.key_hash(&key))
            .await
            .unwrap();
    let validated = validate_upsert(&TemplateUpsert {
        name: Some("碰撞".into()),
        ai_description: None,
        content: Some("碰撞内容".into()),
        defaults: None,
        reference: None,
        tags: None,
        author: None,
        source_url: None,
        nsfw: None,
    })
    .unwrap();
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM templates")
            .fetch_one(&app.state.pool)
            .await
            .unwrap()
    };

    // 前两次撞车，第三次换到新 ID：成功，且用的就是第三个 ID
    let mut ids = vec![taken.clone(), taken.clone(), "freshid00002".to_string()].into_iter();
    let outcome = create_template_row(&app.state, &validated, &owner, || ids.next().unwrap())
        .await
        .unwrap();
    let CreateOutcome::Created(row) = outcome else {
        panic!("应创建成功");
    };
    assert_eq!(row.id, "freshid00002");
    assert_eq!(count().await, 2);

    // 连续 3 次撞车：放弃并返回内部错误，不写入任何新行，也不会第 4 次尝试
    let mut attempts = 0;
    let result = create_template_row(&app.state, &validated, &owner, || {
        attempts += 1;
        taken.clone()
    })
    .await;
    assert!(result.is_err(), "连续撞车应返回错误");
    assert_eq!(attempts, 3, "最多尝试 3 次");
    assert_eq!(count().await, 2);
}

/// 清理任务删除卡住超过 1 小时的 pending 密钥，并按期清空邮箱密文、删除过期记录。
#[tokio::test]
async fn cleanup_removes_stale_pending_keys_and_expired_ciphertext() {
    let Some(app) = app().await else { return };
    let pool = &app.state.pool;
    let email_hmac = app.state.config.account_hmac("cleanup@qq.com");

    let insert_key = |status: &'static str, age: &'static str| {
        let email_hmac = email_hmac.clone();
        async move {
            let id = uuid::Uuid::new_v4();
            sqlx::query(
                "INSERT INTO api_keys (id, key_prefix, key_hash, email_hmac, status, created_at)
                 VALUES ($1, 'iph_test', $2, $3, $4, now() - $5::interval)",
            )
            .bind(id)
            .bind(format!("hash-{id}"))
            .bind(email_hmac)
            .bind(status)
            .bind(age)
            .execute(pool)
            .await
            .unwrap();
            id
        }
    };
    let stale_pending = insert_key("pending_delivery", "2 hours").await;
    let fresh_pending = insert_key("pending_delivery", "5 minutes").await;
    let old_active = insert_key("active", "30 days").await;

    // 一条已过期但密文还在的验证记录
    assert_eq!(app.request_key("cleanup@qq.com").await.status(), 202);
    sqlx::query("UPDATE email_verifications SET expires_at = now() - interval '1 hour'")
        .execute(pool)
        .await
        .unwrap();

    image_prompt_hub::state::run_cleanup(pool).await;

    let exists = |id: uuid::Uuid| async move {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM api_keys WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
            == 1
    };
    assert!(
        !exists(stale_pending).await,
        "超过 1 小时的 pending 密钥应被删除"
    );
    assert!(
        exists(fresh_pending).await,
        "刚创建的 pending 密钥属于进行中的确认，不能动"
    );
    assert!(exists(old_active).await, "active 密钥不受影响");

    let ciphertext_len: i32 =
        sqlx::query_scalar("SELECT length(email_ciphertext) FROM email_verifications")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(ciphertext_len, 0, "过期记录的邮箱密文应被清空");

    // 过期超过 7 天的记录整条删除
    sqlx::query("UPDATE email_verifications SET expires_at = now() - interval '8 days'")
        .execute(pool)
        .await
        .unwrap();
    image_prompt_hub::state::run_cleanup(pool).await;
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM email_verifications")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn admin_hide_and_restore_updates_search_and_catalog() {
    let Some(app) = app().await else { return };
    let owner_key = app
        .create_key_direct("uploader@qq.com", &["read", "write"])
        .await;
    let admin_key = app
        .create_key_direct("admin@qq.com", &["read", "write", "admin"])
        .await;
    let user_key = app
        .create_key_direct("plain@qq.com", &["read", "write"])
        .await;

    let created = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&owner_key)
        .json(&template_json(
            "赛博朋克",
            "一座赛博朋克都市，霓虹与雨夜 {{input}}",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created: serde_json::Value = created.json().await.unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    app.wait_search("赛博朋克", &id, true).await;
    let version: serde_json::Value = app
        .client
        .get(app.url("/v1/catalog/version"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(version["count"], 1);
    let hash_before = version["hash"].as_str().unwrap().to_string();

    // 非 admin 不能隐藏
    assert_eq!(
        app.client
            .post(app.url(&format!("/v1/admin/templates/{id}/hide")))
            .bearer_auth(&user_key)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    let hidden = app
        .client
        .post(app.url(&format!("/v1/admin/templates/{id}/hide")))
        .bearer_auth(&admin_key)
        .send()
        .await
        .unwrap();
    assert_eq!(hidden.status(), 200);
    let hidden: serde_json::Value = hidden.json().await.unwrap();
    assert_eq!(hidden["status"], "hidden");

    app.wait_search("赛博朋克", &id, false).await;
    assert_eq!(
        app.client
            .get(app.url(&format!("/v1/templates/{id}")))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    app.wait_catalog_count(0).await;
    let version: serde_json::Value = app
        .client
        .get(app.url("/v1/catalog/version"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(version["hash"].as_str().unwrap(), hash_before);

    // 恢复后重新出现
    assert_eq!(
        app.client
            .post(app.url(&format!("/v1/admin/templates/{id}/restore")))
            .bearer_auth(&admin_key)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    app.wait_search("都市", &id, true).await;

    // 举报与管理员查看
    let report = app
        .client
        .post(app.url(&format!("/v1/templates/{id}/report")))
        .json(&serde_json::json!({"reason": "测试举报"}))
        .send()
        .await
        .unwrap();
    assert_eq!(report.status(), 202);
    let reports = app
        .client
        .get(app.url("/v1/admin/reports"))
        .bearer_auth(&admin_key)
        .send()
        .await
        .unwrap();
    assert_eq!(reports.status(), 200);
    let reports: serde_json::Value = reports.json().await.unwrap();
    assert_eq!(reports["reports"].as_array().unwrap().len(), 1);

    // 按邮箱查密钥（POST lookup）+ 吊销
    let keys = app
        .client
        .post(app.url("/v1/admin/keys/lookup"))
        .bearer_auth(&admin_key)
        .json(&serde_json::json!({"email": "uploader@qq.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(keys.status(), 200);
    let keys: serde_json::Value = keys.json().await.unwrap();
    let key_id = keys["keys"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(
        app.client
            .delete(app.url(&format!("/v1/admin/keys/{key_id}")))
            .bearer_auth(&admin_key)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        app.client
            .get(app.url("/v1/key"))
            .bearer_auth(&owner_key)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
}

/// 正文控制字符拒绝。
#[tokio::test]
async fn content_control_chars_rejected_over_http() {
    let Some(app) = app().await else { return };
    let key = app
        .create_key_direct("ctrl@qq.com", &["read", "write"])
        .await;

    let bad = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&serde_json::json!({
            "name": "带NUL",
            "content": "内容\u{0000} {{input}}",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);
    let bad: serde_json::Value = bad.json().await.unwrap();
    assert!(bad["error"]["message"]
        .as_str()
        .unwrap()
        .contains("控制字符"));
}

/// tags 的 q 限长与 LIKE 转义；非法列表游标 400。
#[tokio::test]
async fn tags_query_rules_and_cursor_validation() {
    let Some(app) = app().await else { return };
    let key = app
        .create_key_direct("tags@qq.com", &["read", "write"])
        .await;

    let response = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&serde_json::json!({
            "name": "百分号模板",
            "content": "内容 {{input}}",
            "tags": ["100%还原", "a_b"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);

    // % 与 _ 按字面量匹配，不做通配
    let exact = app
        .client
        .get(app.url("/v1/tags?q=100%25%E8%BF%98%E5%8E%9F"))
        .send()
        .await
        .unwrap();
    assert_eq!(exact.status(), 200);
    let exact: serde_json::Value = exact.json().await.unwrap();
    assert_eq!(
        exact["tags"].as_array().unwrap().len(),
        1,
        "百分号应按字面量匹配"
    );

    let underscore = app
        .client
        .get(app.url("/v1/tags?q=a_b"))
        .send()
        .await
        .unwrap();
    let underscore: serde_json::Value = underscore.json().await.unwrap();
    assert_eq!(
        underscore["tags"].as_array().unwrap().len(),
        1,
        "下划线应按字面量匹配"
    );

    // q 超长 → 400
    let long_q = "x".repeat(21);
    let too_long = app
        .client
        .get(app.url(&format!("/v1/tags?q={long_q}")))
        .send()
        .await
        .unwrap();
    assert_eq!(too_long.status(), 400);

    // 非法时间的列表游标 → 400（不变成 500）
    let bad_cursor = image_prompt_hub::api::helpers::encode_cursor(
        &image_prompt_hub::api::helpers::Cursor::List {
            u: "not-a-time".to_string(),
            i: "abc".to_string(),
        },
    );
    let response = app
        .client
        .get(app.url(&format!("/v1/templates?cursor={bad_cursor}")))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "bad_request");
}

#[tokio::test]
async fn catalog_etag_openapi_llms() {
    let Some(app) = app().await else { return };
    let owner_key = app
        .create_key_direct("seeder@qq.com", &["read", "write"])
        .await;
    let created = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&owner_key)
        .json(&template_json("壁纸模板", "一张壁纸 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);

    app.wait_catalog_count(1).await;

    let version: serde_json::Value = app
        .client
        .get(app.url("/v1/catalog/version"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hash = version["hash"].as_str().unwrap().to_string();

    // 显式声明接受 gzip 才拿到 gzip 变体（协商见 catalog_negotiation 测试）
    let catalog = app
        .client
        .get(app.url("/v1/catalog"))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(catalog.status(), 200);
    assert_eq!(catalog.headers().get("content-encoding").unwrap(), "gzip");
    assert_eq!(
        catalog.headers().get("cache-control").unwrap(),
        "public, max-age=300"
    );
    let etag = catalog
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(!etag.starts_with("W/"), "gzip 变体保持强 ETag：{etag}");
    assert_eq!(etag, format!("\"{hash}\""));
    let raw = catalog.bytes().await.unwrap();
    let mut decoder = flate2::read::GzDecoder::new(&raw[..]);
    let mut plain = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut plain).unwrap();
    assert_eq!(image_prompt_hub::crypto::sha256_hex(&plain), hash);
    let package: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(package["format"], "gemini-image-templates");
    assert_eq!(package["version"], 1);

    // If-None-Match → 304
    let not_modified = app
        .client
        .get(app.url("/v1/catalog"))
        .header("If-None-Match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(not_modified.status(), 304);

    // 模板详情 ETag 与 304
    let id = package["templates"][0]["id"].as_str().unwrap().to_string();
    let detail = app
        .client
        .get(app.url(&format!("/v1/templates/{id}")))
        .send()
        .await
        .unwrap();
    let detail_etag = detail
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let detail_304 = app
        .client
        .get(app.url(&format!("/v1/templates/{id}")))
        .header("If-None-Match", &detail_etag)
        .send()
        .await
        .unwrap();
    assert_eq!(detail_304.status(), 304);

    // openapi.json 是合法 JSON 且包含主要路径（含新接口）
    let openapi = app
        .client
        .get(app.url("/openapi.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(openapi.status(), 200);
    let openapi: serde_json::Value = openapi.json().await.unwrap();
    assert_eq!(openapi["openapi"], "3.1.0");
    let paths = openapi["paths"].as_object().unwrap();
    for path in [
        "/v1/templates",
        "/v1/templates/{id}",
        "/v1/templates/batch",
        "/v1/tags",
        "/v1/status",
        "/v1/catalog",
        "/v1/catalog/version",
        "/v1/templates/{id}/report",
        "/v1/keys/request",
        "/v1/keys/verify",
        "/v1/key",
        "/v1/templates/import",
        "/v1/me/templates",
        "/v1/admin/reports",
        "/v1/admin/keys/lookup",
        "/v1/admin/accounts/ban",
        "/v1/admin/accounts/unban",
    ] {
        assert!(paths.contains_key(path), "openapi.json 缺少路径 {path}");
    }

    // 按邮箱查密钥改为 POST，邮箱不再出现在 URL 里
    assert!(
        !paths.contains_key("/v1/admin/keys"),
        "旧的 GET /v1/admin/keys 应已移除"
    );
    assert!(paths["/v1/admin/keys/lookup"]["post"].is_object());
    assert!(paths["/v1/admin/accounts/ban"]["post"].is_object());
    assert!(paths["/v1/admin/accounts/unban"]["post"].is_object());

    // llms.txt 已替换基础地址
    let llms = app.client.get(app.url("/llms.txt")).send().await.unwrap();
    assert_eq!(llms.status(), 200);
    let llms = llms.text().await.unwrap();
    assert!(llms.contains("https://hub.test.example"));
    assert!(!llms.contains("{BASE_URL}"));
    assert!(llms.contains("keys/lookup"), "llms.txt 应包含新接口");
}

#[tokio::test]
async fn rate_limit_returns_429_with_retry_after() {
    let Some(app) = app_with(|config| {
        config.rate_limits.anon_read_per_min = 2;
    })
    .await
    else {
        return;
    };

    let first = app.client.get(app.url("/v1/status")).send().await.unwrap();
    assert_eq!(first.status(), 200);
    let second = app.client.get(app.url("/v1/status")).send().await.unwrap();
    assert_eq!(second.status(), 200);
    let third = app.client.get(app.url("/v1/status")).send().await.unwrap();
    assert_eq!(third.status(), 429);
    let retry_after = third
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .expect("429 应带 Retry-After");
    assert!(retry_after >= 1);
    let body: serde_json::Value = third.json().await.unwrap();
    assert_eq!(body["error"]["code"], "rate_limited");

    // 带密钥走独立限流桶，不受匿名限制影响
    let key = app.create_key_direct("rated@qq.com", &["read"]).await;
    let keyed = app
        .client
        .get(app.url("/v1/status"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(keyed.status(), 200);
}

/// 邮件里的吊销链接：确认页、吊销、幂等与响应头。
#[tokio::test]
async fn revoke_link_flow() {
    let Some(app) = app().await else { return };

    // 申请一把密钥，从邮件正文里拿到吊销链接
    let key = app.issue_key("revoke@qq.com").await;
    let link = app.latest_revoke_link().await;
    assert!(
        link.starts_with("https://hub.test.example/v1/keys/revoke?token="),
        "链接必须以 PUBLIC_BASE_URL 开头：{link}"
    );
    let token = link.split("token=").nth(1).unwrap().to_string();

    // GET 确认页：含密钥前缀与 POST 表单，且不改变状态
    let page = app
        .client
        .get(app.url(&format!("/v1/keys/revoke?token={token}")))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    for header in [
        "content-security-policy",
        "x-frame-options",
        "cache-control",
        "referrer-policy",
    ] {
        assert!(
            page.headers().contains_key(header),
            "吊销页缺少响应头 {header}"
        );
    }
    let html = page.text().await.unwrap();
    let prefix = &key[..key.len().min(12)];
    assert!(
        html.contains(prefix),
        "确认页应写明密钥前缀 {prefix}：{html}"
    );
    assert!(
        html.contains("<form method=\"post\" action=\"/v1/keys/revoke\">"),
        "缺少 POST 表单"
    );
    assert!(html.contains("确认吊销"), "缺少确认吊销按钮");
    assert!(html.contains("插件会立刻失效"), "缺少失效说明");
    assert!(html.contains("重新申请新密钥"), "缺少重新申请说明");
    assert_eq!(
        app.client
            .get(app.url("/v1/key"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "GET 确认页不应改变密钥状态"
    );

    // POST 吊销生效
    let confirm = app
        .client
        .post(app.url("/v1/keys/revoke"))
        .form(&[("token", token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(confirm.status(), 200);
    assert!(confirm.text().await.unwrap().contains("密钥已吊销"));
    assert_eq!(
        app.client
            .get(app.url("/v1/key"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "吊销后密钥应立即失效"
    );

    // 幂等：重复 POST 与再次 GET 都显示通用无效页
    for repeat in 0..2 {
        let again = app
            .client
            .post(app.url("/v1/keys/revoke"))
            .form(&[("token", token.as_str())])
            .send()
            .await
            .unwrap();
        assert_eq!(again.status(), 200);
        assert!(
            again.text().await.unwrap().contains("链接无效"),
            "第 {repeat} 次重复提交"
        );
    }
    let page = app
        .client
        .get(app.url(&format!("/v1/keys/revoke?token={token}")))
        .send()
        .await
        .unwrap();
    assert!(page.text().await.unwrap().contains("链接无效"));
}

/// 重置后旧吊销链接失效、新链接有效；非 active 密钥的令牌无效。
#[tokio::test]
async fn revoke_link_after_reset_and_non_active_keys() {
    let Some(app) = app().await else { return };

    // 第一把密钥及其链接
    let _first = app.issue_key("rotate@qq.com").await;
    let first_token = app
        .latest_revoke_link()
        .await
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();

    // 同一邮箱重置拿第二把（吊销第一把）
    app.backdate_verifications("rotate@qq.com").await;
    let _second = app.issue_key("rotate@qq.com").await;
    let second_token = app
        .latest_revoke_link()
        .await
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();

    // 旧链接：密钥已非 active → 通用无效页，POST 同样无效
    for token in [&first_token, &second_token] {
        let page = app
            .client
            .get(app.url(&format!("/v1/keys/revoke?token={token}")))
            .send()
            .await
            .unwrap();
        let body = page.text().await.unwrap();
        if token == &first_token {
            assert!(body.contains("链接无效"), "重置后旧链接应失效");
        } else {
            assert!(body.contains("确认吊销"), "新链接应有效");
        }
    }
    let post = app
        .client
        .post(app.url("/v1/keys/revoke"))
        .form(&[("token", first_token.as_str())])
        .send()
        .await
        .unwrap();
    assert!(post.text().await.unwrap().contains("链接无效"));

    // 非 active：pending_delivery 与已吊销密钥的令牌都无效
    let email_hmac = app.state.config.account_hmac("pending@qq.com");
    let pending_key = image_prompt_hub::crypto::generate_api_key();
    let pending_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO api_keys (id, key_prefix, key_hash, email_hmac, scopes, status)
         VALUES ($1, $2, $3, $4, '{read}', 'pending_delivery')",
    )
    .bind(pending_id)
    .bind(image_prompt_hub::crypto::key_prefix(&pending_key))
    .bind(app.state.config.key_hash(&pending_key))
    .bind(&email_hmac)
    .execute(&app.state.pool)
    .await
    .unwrap();
    let revoked_key = image_prompt_hub::crypto::generate_api_key();
    let revoked_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO api_keys (id, key_prefix, key_hash, email_hmac, scopes, status, revoked_at)
         VALUES ($1, $2, $3, $4, '{read}', 'revoked', now())",
    )
    .bind(revoked_id)
    .bind(image_prompt_hub::crypto::key_prefix(&revoked_key))
    .bind(app.state.config.key_hash(&revoked_key))
    .bind(&email_hmac)
    .execute(&app.state.pool)
    .await
    .unwrap();

    for key_id in [pending_id, revoked_id] {
        let token = app.state.config.revoke_token(key_id);
        let page = app
            .client
            .get(app.url(&format!("/v1/keys/revoke?token={token}")))
            .send()
            .await
            .unwrap();
        assert!(
            page.text().await.unwrap().contains("链接无效"),
            "非 active 密钥应无效"
        );
    }
}

/// 吊销接口受 RATE_KEY_VERIFY_PER_HOUR 限流。
#[tokio::test]
async fn revoke_link_rate_limited() {
    let Some(app) = app_with(|config| {
        config.rate_limits.key_verify_per_hour = 3;
    })
    .await
    else {
        return;
    };

    let key = app.issue_key("rate-revoke@qq.com").await;
    let token = app
        .latest_revoke_link()
        .await
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();

    // 限流窗口内第 4 次访问返回 429
    let mut got_429 = false;
    for _ in 0..4 {
        let response = app
            .client
            .get(app.url(&format!("/v1/keys/revoke?token={token}")))
            .send()
            .await
            .unwrap();
        if response.status() == 429 {
            got_429 = true;
            break;
        }
    }
    assert!(got_429, "吊销接口应受 verify 限流约束");
    // 密钥未被吊销（限流挡下的是查看，不是吊销动作）
    assert_eq!(
        app.client
            .get(app.url("/v1/key"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}

/// 根路径导航页：GET/HEAD、内容、安全头。
#[tokio::test]
async fn root_index_page() {
    let Some(app) = app().await else { return };

    let response = app.client.get(app.url("/")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert!(response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/html")));
    for header in [
        "content-security-policy",
        "x-frame-options",
        "cache-control",
        "referrer-policy",
    ] {
        assert!(
            response.headers().contains_key(header),
            "导航页缺少 {header}"
        );
    }
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let html = response.text().await.unwrap();
    for link in [
        "/llms.txt",
        "/openapi.json",
        "/v1/status",
        "/v1/catalog/version",
    ] {
        assert!(
            html.contains(&format!("href=\"{link}\"")),
            "缺少导航链接 {link}"
        );
    }
    assert!(html.contains("公开检索与下载，申请密钥后可上传"));
    assert!(html.contains("如何申请密钥"));

    // HEAD 同样可用
    let head = app.client.head(app.url("/")).send().await.unwrap();
    assert_eq!(head.status(), 200);
    assert!(head.headers().contains_key("content-security-policy"));
}

/// 索引对账任务：命令行/库级封禁隐藏的模板在短间隔内从检索与目录快照里消失，
/// 解封（不恢复模板）后依旧不可检索。
#[tokio::test]
async fn hidden_templates_disappear_via_index_sync_task() {
    let Some(app) = app_with(|config| {
        config.index_sync_interval_secs = 1;
        config.catalog_debounce_secs = 0;
    })
    .await
    else {
        return;
    };
    let key = app
        .create_key_direct("sync@qq.com", &["read", "write"])
        .await;

    // 上传并等待可检索
    let response = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&template_json("赛博朋克同步", "赛博朋克风格 {{input}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    let created: serde_json::Value = response.json().await.unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    app.wait_search("赛博朋克", &id, true).await;

    let version: serde_json::Value = app
        .client
        .get(app.url("/v1/catalog/version"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hash_before = version["hash"].as_str().unwrap().to_string();

    // 绕过 HTTP 接口直接在库里封禁并隐藏（模拟命令行 admin ban --hide-templates）
    let email_hmac = app.state.config.account_hmac("sync@qq.com");
    image_prompt_hub::accounts::ban(&app.state.pool, &email_hmac, "对账测试", true)
        .await
        .expect("封禁失败");

    // 对账任务在约 1 秒内提交删除：检索消失、快照哈希变化
    app.wait_search("赛博朋克", &id, false).await;
    app.wait_catalog_hash_changes(&hash_before).await;

    // 解封不恢复模板：依旧不可检索、不在快照里
    assert!(
        image_prompt_hub::accounts::unban(&app.state.pool, &email_hmac)
            .await
            .expect("解封失败")
    );
    let listed = app
        .client
        .get(app.url("/v1/templates"))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert!(
        !listed["templates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["id"].as_str() == Some(id.as_str())),
        "解封后模板仍应保持隐藏"
    );
}
