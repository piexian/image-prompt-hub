//! HTTP 层的限流、缓存头、输入边界与错误格式（需要数据库；未设置 DATABASE_URL 时跳过）。

mod common;

use image_prompt_hub::api::helpers::{encode_cursor, Cursor};
use image_prompt_hub::config::Config;

async fn app_with(adjust: impl FnOnce(&mut Config)) -> Option<common::TestApp> {
    common::setup(adjust).await
}

fn template_body(name: &str, content: &str) -> serde_json::Value {
    serde_json::json!({"name": name, "content": content, "tags": ["硬化"]})
}

async fn upload(app: &common::TestApp, key: &str, name: &str, content: &str) -> String {
    let response = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(key)
        .json(&template_body(name, content))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    let body: serde_json::Value = response.json().await.unwrap();
    body["id"].as_str().unwrap().to_string()
}

fn cache_control(response: &reqwest::Response) -> String {
    response
        .headers()
        .get("cache-control")
        .expect("所有响应都应带 Cache-Control")
        .to_str()
        .unwrap()
        .to_string()
}

/// GET /v1/key 计入带密钥的读限流。
#[tokio::test]
async fn key_info_counts_against_keyed_read_limit() {
    let Some(app) = app_with(|config| config.rate_limits.keyed_read_per_min = 3).await else {
        return;
    };
    let key = app.create_key_direct("probe@qq.com", &["read"]).await;
    for round in 1..=3 {
        let response = app
            .client
            .get(app.url("/v1/key"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "第 {round} 次应通过");
    }
    let limited = app
        .client
        .get(app.url("/v1/key"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status(), 429);
    assert!(limited.headers().contains_key("retry-after"));
    let body: serde_json::Value = limited.json().await.unwrap();
    assert_eq!(body["error"]["code"], "rate_limited");
}

/// 认证失败窗口只统计 401：匿名与有效密钥的请求不消耗额度；
/// 无效密钥达到上限后，该 IP 的所有带 Bearer 请求（包括有效密钥）都被拒。
#[tokio::test]
async fn auth_failure_window_counts_only_failures() {
    let Some(app) = app_with(|config| {
        config.rate_limits.auth_failure_per_min = 3;
        config.trust_cf_connecting_ip = true;
    })
    .await
    else {
        return;
    };
    let key = app.create_key_direct("auth@qq.com", &["read"]).await;

    // 匿名请求不经过认证窗口
    for _ in 0..6 {
        let response = app.client.get(app.url("/v1/status")).send().await.unwrap();
        assert_eq!(response.status(), 200, "匿名请求不应受认证失败窗口影响");
    }
    // 有效密钥请求再多也不扣减额度
    for _ in 0..10 {
        let response = app
            .client
            .get(app.url("/v1/key"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "有效密钥不应消耗失败额度");
    }

    // 无效密钥 3 次 401 达到上限
    for _ in 0..3 {
        let response = app
            .client
            .get(app.url("/v1/key"))
            .bearer_auth("iph_invalid")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
    }
    // 第 4 次（无论密钥有效与否）在查库前直接 429
    let blocked = app
        .client
        .get(app.url("/v1/key"))
        .bearer_auth("iph_invalid")
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), 429);
    assert!(blocked.headers().contains_key("retry-after"));
    // 取舍：超限后同 IP 的有效密钥也被拒（挡洪泛优先）
    let valid_blocked = app
        .client
        .get(app.url("/v1/key"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(valid_blocked.status(), 429, "同 IP 连坐是文档化的取舍");

    // 不同 IP 互不影响（借 CF-Connecting-IP 区分）
    let other = app
        .client
        .get(app.url("/v1/key"))
        .bearer_auth(&key)
        .header("cf-connecting-ip", "203.0.113.99")
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), 200, "不同 IP 不应受影响");
}

/// 同一 /64 网段内轮换 IPv6 地址共享限额；不同网段互不影响。
#[tokio::test]
async fn ipv6_addresses_in_one_slash64_share_the_limit() {
    let Some(app) = app_with(|config| {
        config.trust_cf_connecting_ip = true;
        config.rate_limits.anon_read_per_min = 3;
    })
    .await
    else {
        return;
    };
    let status_for = |ip: &'static str| {
        let app = &app;
        async move {
            app.client
                .get(app.url("/v1/status"))
                .header("cf-connecting-ip", ip)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    assert_eq!(status_for("2001:db8:1:2::1").await, 200);
    assert_eq!(status_for("2001:db8:1:2:aaaa:bbbb:cccc:dddd").await, 200);
    assert_eq!(status_for("2001:db8:1:2::ffff").await, 200);
    assert_eq!(
        status_for("2001:db8:1:2::4").await,
        429,
        "同一 /64 内换地址不能绕过限额"
    );
    assert_eq!(status_for("2001:db8:1:3::1").await, 200, "不同网段独立计数");
    assert_eq!(status_for("203.0.113.9").await, 200, "IPv4 按完整地址计数");
}

/// 公开接口的成功响应可缓存，错误响应、写操作、私有接口与带密钥的请求都不缓存。
#[tokio::test]
async fn cache_headers_follow_the_policy_over_http() {
    let Some(app) = app_with(|_| {}).await else {
        return;
    };
    let key = app
        .create_key_direct("cache-http@qq.com", &["read", "write"])
        .await;
    let id = upload(&app, &key, "缓存模板", "缓存测试内容 {{input}}").await;
    app.wait_catalog_count(1).await;

    let get = |path: String| {
        let app = &app;
        async move { app.client.get(app.url(&path)).send().await.unwrap() }
    };

    // 公开读接口的成功响应
    for path in [
        format!("/v1/templates/{id}"),
        "/v1/templates".to_string(),
        "/v1/templates/batch?ids=".to_string() + &id,
        "/v1/tags".to_string(),
        "/v1/status".to_string(),
        "/v1/catalog/version".to_string(),
        "/openapi.json".to_string(),
        "/llms.txt".to_string(),
    ] {
        let response = get(path.clone()).await;
        assert_eq!(response.status(), 200, "{path}");
        assert_eq!(cache_control(&response), "public, max-age=60", "{path}");
    }
    let catalog = get("/v1/catalog".to_string()).await;
    assert_eq!(cache_control(&catalog), "public, max-age=300");

    // 304 沿用公开缓存策略
    let etag = catalog.headers()["etag"].to_str().unwrap().to_string();
    let not_modified = app
        .client
        .get(app.url("/v1/catalog"))
        .header("If-None-Match", etag)
        .send()
        .await
        .unwrap();
    assert_eq!(not_modified.status(), 304);
    assert_eq!(cache_control(&not_modified), "public, max-age=300");

    // 公开路径上的错误响应不进共享缓存
    let missing = get("/v1/templates/doesnotexist".to_string()).await;
    assert_eq!(missing.status(), 404);
    assert_eq!(cache_control(&missing), "no-store");
    let bad_limit = get("/v1/templates?limit=0".to_string()).await;
    assert_eq!(bad_limit.status(), 400);
    assert_eq!(cache_control(&bad_limit), "no-store");
    let unknown = get("/v1/no-such-endpoint".to_string()).await;
    assert_eq!(unknown.status(), 404);
    assert_eq!(cache_control(&unknown), "no-store");
    assert_eq!(unknown.headers()["x-content-type-options"], "nosniff");
    let body: serde_json::Value = unknown.json().await.unwrap();
    assert_eq!(
        body["error"]["code"], "not_found",
        "未匹配路由也返回统一的 JSON 错误"
    );

    // 公开路径上的写操作
    let report = app
        .client
        .post(app.url(&format!("/v1/templates/{id}/report")))
        .json(&serde_json::json!({"reason": "缓存测试"}))
        .send()
        .await
        .unwrap();
    assert_eq!(report.status(), 202);
    assert_eq!(cache_control(&report), "no-store");
    let anonymous_create = app
        .client
        .post(app.url("/v1/templates"))
        .json(&template_body("匿名", "内容"))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous_create.status(), 401);
    assert_eq!(cache_control(&anonymous_create), "no-store");

    // 私有接口：匿名与带密钥
    let anonymous_key = get("/v1/key".to_string()).await;
    assert_eq!(anonymous_key.status(), 401);
    assert_eq!(cache_control(&anonymous_key), "no-store");
    for path in [
        "/v1/key",
        "/v1/me/templates",
        "/v1/templates",
        "/v1/catalog",
    ] {
        let response = app
            .client
            .get(app.url(path))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        assert_eq!(
            cache_control(&response),
            "private, no-store",
            "带 Authorization 的请求一律私有：{path}"
        );
    }
    let bad_key = app
        .client
        .get(app.url("/v1/status"))
        .bearer_auth("iph_wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(bad_key.status(), 401);
    assert_eq!(cache_control(&bad_key), "private, no-store");
}

/// 限流响应（429）本身也不能被缓存。
#[tokio::test]
async fn rate_limited_responses_are_not_cacheable() {
    let Some(app) = app_with(|config| config.rate_limits.anon_read_per_min = 1).await else {
        return;
    };
    assert_eq!(
        app.client
            .get(app.url("/v1/status"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let limited = app.client.get(app.url("/v1/status")).send().await.unwrap();
    assert_eq!(limited.status(), 429);
    assert_eq!(cache_control(&limited), "no-store");
    assert!(limited.headers().contains_key("retry-after"));
}

/// 请求里的 NUL 一律是 400，而不是让 PostgreSQL 报错变成 500。
#[tokio::test]
async fn nul_characters_in_inputs_never_cause_server_errors() {
    let Some(app) = app_with(|_| {}).await else {
        return;
    };
    let key = app
        .create_key_direct("nul@qq.com", &["read", "write", "admin"])
        .await;
    let id = upload(&app, &key, "NUL 测试", "正常内容 {{input}}").await;

    // 路径与查询参数里的 %00
    for path in [
        "/v1/templates/%00".to_string(),
        "/v1/tags?q=%00".to_string(),
        "/v1/templates?tag=%00".to_string(),
        "/v1/templates/batch?ids=%00".to_string(),
        format!("/v1/templates/batch?ids={id},%00"),
    ] {
        let response = app.client.get(app.url(&path)).send().await.unwrap();
        let status = response.status().as_u16();
        assert!(
            (400..500).contains(&status),
            "{path} 应是 4xx，实际 {status}"
        );
    }

    // 游标 JSON 里的 \u0000（base64 编码后不会被 URL 层拦住）
    let cursor = encode_cursor(&Cursor::List {
        u: "2026-01-01T00:00:00Z".to_string(),
        i: "a\u{0}b".to_string(),
    });
    let response = app
        .client
        .get(app.url(&format!("/v1/templates?cursor={cursor}")))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    // JSON 请求体里的 \u0000
    let report = app
        .client
        .post(app.url(&format!("/v1/templates/{id}/report")))
        .json(&serde_json::json!({"reason": "含\u{0}控制字符"}))
        .send()
        .await
        .unwrap();
    assert_eq!(report.status(), 400);
    let ban = app
        .client
        .post(app.url("/v1/admin/accounts/ban"))
        .bearer_auth(&key)
        .json(
            &serde_json::json!({"email": "x@qq.com", "reason": "含\u{0}", "hide_templates": false}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(ban.status(), 400);
    // 出处链接里的 NUL 在校验阶段就被拒绝，不会走到数据库
    let bad_source = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&serde_json::json!({
            "name": "出处含NUL",
            "content": "内容 {{input}}",
            "source_url": "https://example.com/a\u{0}b",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_source.status(), 400);
    let bad_source: serde_json::Value = bad_source.json().await.unwrap();
    assert!(bad_source["error"]["message"]
        .as_str()
        .unwrap()
        .contains("source_url"));
    // 名称、标签、说明、署名里的控制字符被剥掉后正常保存
    let created = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&serde_json::json!({
            "name": "名\u{0}称",
            "content": "内容 {{input}}",
            "tags": ["标\u{0}签"],
            "ai_description": "说\u{0}明",
            "author": "作\u{0}者",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created: serde_json::Value = created.json().await.unwrap();
    assert_eq!(created["name"], "名称");
    assert_eq!(created["tags"][0], "标签");
}

/// 管理接口的请求体格式错误同样返回统一的 JSON 错误；权限检查先于请求体解析。
#[tokio::test]
async fn admin_endpoints_report_bad_bodies_as_json_errors() {
    let Some(app) = app_with(|_| {}).await else {
        return;
    };
    let admin = app
        .create_key_direct("json-admin@qq.com", &["read", "write", "admin"])
        .await;
    let plain = app
        .create_key_direct("json-plain@qq.com", &["read", "write"])
        .await;

    for path in [
        "/v1/admin/keys/lookup",
        "/v1/admin/accounts/ban",
        "/v1/admin/accounts/unban",
    ] {
        let bad = app
            .client
            .post(app.url(path))
            .bearer_auth(&admin)
            .header("content-type", "application/json")
            .body("{not json")
            .send()
            .await
            .unwrap();
        assert_eq!(bad.status(), 400, "{path}");
        let body: serde_json::Value = bad.json().await.unwrap();
        assert_eq!(body["error"]["code"], "bad_request", "{path}");

        let forbidden = app
            .client
            .post(app.url(path))
            .bearer_auth(&plain)
            .header("content-type", "application/json")
            .body("{not json")
            .send()
            .await
            .unwrap();
        assert_eq!(forbidden.status(), 403, "{path}：无权限时先返回 403");
    }

    // 定位账号必须二选一：两个都给、两个都不给都是 400，且不会执行任何封禁
    let both = app
        .client
        .post(app.url("/v1/admin/accounts/ban"))
        .bearer_auth(&admin)
        .json(&serde_json::json!({
            "email": "json-plain@qq.com",
            "key_id": uuid::Uuid::new_v4(),
            "reason": "两个都给",
            "hide_templates": false,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(both.status(), 400);
    let banned: i64 = sqlx::query_scalar("SELECT count(*) FROM banned_accounts")
        .fetch_one(&app.state.pool)
        .await
        .unwrap();
    assert_eq!(banned, 0);
    let missing = app
        .client
        .post(app.url("/v1/admin/accounts/ban"))
        .bearer_auth(&admin)
        .json(&serde_json::json!({"reason": "没有定位", "hide_templates": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 400);
}

/// 请求体上限：普通接口 256KB，导入接口 1MB；超限返回统一的 413。
#[tokio::test]
async fn body_limits_differ_between_create_and_import() {
    let Some(app) = app_with(|_| {}).await else {
        return;
    };
    let key = app
        .create_key_direct("limits@qq.com", &["read", "write"])
        .await;

    let big = "字".repeat(100_000); // 约 300KB
    let create = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&serde_json::json!({"name": "超大", "content": big}))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), 413);
    let body: serde_json::Value = create.json().await.unwrap();
    assert_eq!(body["error"]["code"], "payload_too_large");

    // 导入接口：300KB 可以收下（条目本身因内容超长被逐条拒绝），1MB 以上才是 413
    let items = |filler: &str| -> Vec<serde_json::Value> {
        (0..50)
            .map(|i| serde_json::json!({"name": format!("条目{i}"), "content": filler}))
            .collect()
    };
    let accepted = app
        .client
        .post(app.url("/v1/templates/import"))
        .bearer_auth(&key)
        .json(&serde_json::json!({
            "format": "gemini-image-templates",
            "version": 1,
            "templates": items(&"a".repeat(6000)),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), 200, "300KB 的导入包应被接收");

    let oversized = app
        .client
        .post(app.url("/v1/templates/import"))
        .bearer_auth(&key)
        .json(&serde_json::json!({
            "format": "gemini-image-templates",
            "version": 1,
            "templates": items(&"b".repeat(30_000)),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), 413);
    let body: serde_json::Value = oversized.json().await.unwrap();
    assert_eq!(body["error"]["code"], "payload_too_large");
}

/// 检索翻页：每页恰好 limit 条，页与页不重叠，最后一页没有下一页游标。
#[tokio::test]
async fn search_pagination_returns_exact_pages() {
    let Some(app) = app_with(|_| {}).await else {
        return;
    };
    let key = app
        .create_key_direct("pages@qq.com", &["read", "write"])
        .await;
    let mut ids = Vec::new();
    for i in 0..5 {
        ids.push(
            upload(
                &app,
                &key,
                &format!("分页模板{i}"),
                &format!("分页检索 内容{i}"),
            )
            .await,
        );
    }
    for id in &ids {
        app.wait_search("分页检索", id, true).await;
    }

    let mut seen = std::collections::HashSet::new();
    let mut cursor: Option<String> = None;
    let mut page_sizes = Vec::new();
    for _ in 0..5 {
        let mut url = "/v1/templates?q=%E5%88%86%E9%A1%B5%E6%A3%80%E7%B4%A2&limit=2".to_string();
        if let Some(cursor) = &cursor {
            url.push_str(&format!("&cursor={cursor}"));
        }
        let page: serde_json::Value = app
            .client
            .get(app.url(&url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let templates = page["templates"].as_array().unwrap();
        page_sizes.push(templates.len());
        for template in templates {
            assert!(
                seen.insert(template["id"].as_str().unwrap().to_string()),
                "页与页之间不应重复"
            );
            assert!(template["snippet"].is_string());
        }
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_string()),
            None => break,
        }
    }
    assert_eq!(page_sizes, [2, 2, 1]);
    assert_eq!(seen.len(), 5);
}

/// 不带关键词的列表按更新时间倒序翻页（游标里的时间以带类型的值绑定）：
/// 每页恰好 limit 条，不重复不遗漏；带 tag 过滤时同样成立。
#[tokio::test]
async fn list_pagination_walks_every_template_once() {
    let Some(app) = app_with(|_| {}).await else {
        return;
    };
    let key = app
        .create_key_direct("walk@qq.com", &["read", "write"])
        .await;
    let mut created = Vec::new();
    for i in 0..5 {
        let response = app
            .client
            .post(app.url("/v1/templates"))
            .bearer_auth(&key)
            .json(&serde_json::json!({
                "name": format!("翻页{i}"),
                "content": format!("内容{i}"),
                "tags": if i % 2 == 0 { vec!["偶数", "全部"] } else { vec!["奇数", "全部"] },
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201);
        let body: serde_json::Value = response.json().await.unwrap();
        created.push(body["id"].as_str().unwrap().to_string());
    }

    // 本机时钟可能被回拨，创建顺序不保证与 updated_at 顺序一致；
    // 用固定基准时间加创建序偏移作为参数写入递增时间戳，完全不依赖系统时钟。
    let base = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00+00:00")
        .expect("固定基准时间有效")
        .with_timezone(&chrono::Utc);
    for (i, id) in created.iter().enumerate() {
        let at = base + chrono::Duration::seconds(i as i64);
        sqlx::query("UPDATE templates SET created_at = $1, updated_at = $1 WHERE id = $2")
            .bind(at)
            .bind(id)
            .execute(&app.state.pool)
            .await
            .expect("写入递增时间戳失败");
    }

    for (tag, expected) in [("", 5usize), ("全部", 5), ("偶数", 3), ("奇数", 2)] {
        let mut seen = Vec::new();
        let mut sizes = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut query = vec![("limit", "2".to_string())];
            if !tag.is_empty() {
                query.push(("tag", tag.to_string()));
            }
            if let Some(cursor) = &cursor {
                query.push(("cursor", cursor.clone()));
            }
            let page: serde_json::Value = app
                .client
                .get(app.url("/v1/templates"))
                .query(&query)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let templates = page["templates"].as_array().unwrap();
            sizes.push(templates.len());
            seen.extend(
                templates
                    .iter()
                    .map(|t| t["id"].as_str().unwrap().to_string()),
            );
            match page["next_cursor"].as_str() {
                Some(next) => cursor = Some(next.to_string()),
                None => break,
            }
            assert!(sizes.len() <= 5, "翻页没有终止");
        }
        assert_eq!(seen.len(), expected, "tag={tag:?} sizes={sizes:?}");
        let unique: std::collections::HashSet<_> = seen.iter().collect();
        assert_eq!(unique.len(), expected, "tag={tag:?} 页与页之间不应重复");
        assert!(
            sizes[..sizes.len() - 1].iter().all(|size| *size == 2),
            "{sizes:?}"
        );
        // 倒序：最后创建的最先出现
        if tag.is_empty() {
            let expected_order: Vec<_> = created.iter().rev().cloned().collect();
            assert_eq!(seen, expected_order);
        }
    }
}

/// 状态接口公开新增的限流与额度说明。
#[tokio::test]
async fn status_describes_all_public_limits() {
    let Some(app) = app_with(|_| {}).await else {
        return;
    };
    let status: serde_json::Value = app
        .client
        .get(app.url("/v1/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let limits = &status["rate_limits"];
    for key in [
        "anonymous_read_per_minute_per_ip",
        "keyed_read_per_minute_per_key",
        "write_per_minute_per_key",
        "key_request_per_hour_per_ip",
        "key_verify_per_hour_per_ip",
        "report_per_hour_per_ip",
        "auth_failure_per_minute_per_ip",
        "account_create_per_hour",
        "account_template_limit",
    ] {
        assert!(limits[key].is_number(), "状态接口缺少 {key}：{limits}");
    }
    assert_eq!(limits["account_create_per_hour"], 100);
    assert_eq!(limits["account_template_limit"], 1000);
}
