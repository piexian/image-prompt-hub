//! Cloudflare 发信的本地假服务器测试（不需要数据库）。

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use image_prompt_hub::email::cloudflare::CloudflareMailer;
use image_prompt_hub::email::Mailer;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// 记录请求并按脚本回复的假 Cloudflare 端点。
struct FakeApi {
    calls: AtomicUsize,
    status: StatusCode,
    body: serde_json::Value,
    last_request: tokio::sync::Mutex<Option<serde_json::Value>>,
}

async fn send_endpoint(State(api): State<Arc<FakeApi>>, body: axum::extract::Request) -> Response {
    api.calls.fetch_add(1, Ordering::SeqCst);
    let bytes = axum::body::to_bytes(body.into_body(), 1024 * 1024)
        .await
        .unwrap();
    *api.last_request.lock().await = Some(serde_json::from_slice(&bytes).unwrap());
    (api.status, Json(api.body.clone())).into_response()
}

use axum::response::{IntoResponse, Response};

async fn spawn_fake(status: StatusCode, body: serde_json::Value) -> (String, Arc<FakeApi>) {
    let api = Arc::new(FakeApi {
        calls: AtomicUsize::new(0),
        status,
        body,
        last_request: tokio::sync::Mutex::new(None),
    });
    let app = Router::new()
        .route(
            "/accounts/{account_id}/email/sending/send",
            post(send_endpoint),
        )
        .with_state(api.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), api)
}

fn mailer(endpoint_base: &str) -> CloudflareMailer {
    CloudflareMailer::with_endpoint_base(
        endpoint_base,
        "acct",
        "tok",
        "noreply@example.com",
        "模板服务",
    )
}

#[tokio::test]
async fn success_sends_expected_payload() {
    let (base, api) = spawn_fake(
        StatusCode::OK,
        serde_json::json!({"success": true, "result": {}}),
    )
    .await;
    let mailer = mailer(&base);
    mailer
        .send("user@qq.com", "主题", "第一行\n第二行")
        .await
        .unwrap();
    assert_eq!(api.calls.load(Ordering::SeqCst), 1);
    let request = api.last_request.lock().await.clone().unwrap();
    assert_eq!(request["to"], "user@qq.com");
    assert_eq!(request["from"]["email"], "noreply@example.com");
    assert_eq!(request["from"]["name"], "模板服务");
    assert_eq!(request["subject"], "主题");
    assert_eq!(request["text"], "第一行\n第二行");
    assert_eq!(request["html"], "第一行<br>第二行");
}

#[tokio::test]
async fn error_cases_are_failures() {
    let cases = [
        (StatusCode::TOO_MANY_REQUESTS, serde_json::json!({}), "限流"),
        (StatusCode::UNAUTHORIZED, serde_json::json!({}), "认证失败"),
        (StatusCode::BAD_GATEWAY, serde_json::json!({}), "HTTP 502"),
        (
            StatusCode::OK,
            serde_json::json!({"success": false, "errors": [{"code": 1003, "message": "bad"}]}),
            "[1003] bad",
        ),
        (
            StatusCode::OK,
            serde_json::json!({"success": true, "result": {"permanent_bounces": ["user@qq.com"]}}),
            "永久退信",
        ),
    ];
    for (status, body, expect) in cases {
        let (base, _) = spawn_fake(status, body).await;
        let error = mailer(&base)
            .send("user@qq.com", "s", "b")
            .await
            .unwrap_err();
        assert!(error.contains(expect), "错误信息不符：{error}");
    }
}
