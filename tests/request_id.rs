//! 请求 ID 与 CF-Ray 日志字段的集成验证。
//! 本文件安装自己的 tracing 捕获订阅器（先于 common 的全局初始化），
//! 断言访问日志里确实带上了 request_id 与合规的 cf_ray。

mod common;

use std::sync::{Mutex, OnceLock};

/// 捕获到的日志行（字段以 name=value 形式拼接）。
static LOGS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

fn logs() -> &'static Mutex<Vec<String>> {
    LOGS.get_or_init(|| Mutex::new(Vec::new()))
}

struct CaptureLayer;

struct FieldVisitor(String);

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!("{:?}={:?} ", field.name(), value));
    }
}

impl<S> tracing_subscriber::Layer<S> for CaptureLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // 只收访问日志（消息为 "access"）
        let mut visitor = FieldVisitor(String::new());
        event.record(&mut visitor);
        if visitor.0.contains("\"message\"=access") {
            logs().lock().unwrap().push(visitor.0);
        }
    }
}

fn install_capture() {
    use tracing_subscriber::layer::SubscriberExt;
    let _ = tracing::subscriber::set_global_default(
        tracing_subscriber::Registry::default().with(CaptureLayer),
    );
}

/// 按唯一请求路径找对应的访问日志行：测试并行时全局日志可能交错，
/// 用每次请求独有的路径定位，不受其他测试插队影响。
fn access_line_for(path: &str) -> String {
    let all = logs().lock().unwrap();
    all.iter()
        .rev()
        .find(|line| line.contains(&format!("\"path\"={path}")))
        .cloned()
        .unwrap_or_default()
}

/// 服务端生成请求 ID：每个响应都有、是合法 UUID、两个请求不同、客户端传入的同名头被忽略。
#[tokio::test]
async fn every_response_gets_unique_request_id() {
    install_capture();
    let Some(app) = common::setup(|_| {}).await else {
        return;
    };

    for path in ["/v1/status", "/llms.txt", "/no-such-route"] {
        let response = app.client.get(app.url(path)).send().await.unwrap();
        let id = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(!id.is_empty(), "{path} 缺少 X-Request-Id");
        assert!(
            uuid::Uuid::parse_str(&id).is_ok(),
            "{path} 的 X-Request-Id 不是合法 UUID：{id}"
        );
        // 404 由路由层生成，同样要带头
        if path == "/no-such-route" {
            assert_eq!(response.status(), 404);
            assert!(!id.is_empty());
        }
    }

    // 两次请求 ID 不同
    let first = app
        .client
        .get(app.url("/v1/status"))
        .send()
        .await
        .unwrap()
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let second = app
        .client
        .get(app.url("/v1/status"))
        .send()
        .await
        .unwrap()
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(first, second);

    // 客户端伪造的同名头被忽略
    let forged = "00000000-0000-0000-0000-000000000000";
    let response = app
        .client
        .get(app.url("/v1/status"))
        .header("X-Request-Id", forged)
        .send()
        .await
        .unwrap();
    let got = response
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap();
    assert_ne!(got, forged, "客户端传来的请求 ID 必须被忽略");

    // 错误响应（4xx）也带头
    let denied = app
        .client
        .post(app.url("/v1/templates"))
        .json(&serde_json::json!({"name": "x", "content": "y {{input}}"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 401);
    assert!(denied.headers().contains_key("x-request-id"));

    // 访问日志带上 request_id 字段，且伪造头那次请求的 ID 与响应头一致
    let all = logs().lock().unwrap().join("\n");
    assert!(all.contains("request_id"), "访问日志缺少 request_id：{all}");
    assert!(
        all.lines().any(|line| line.contains(got)),
        "日志里应有与响应头一致的请求 ID {got}：{all}"
    );
}

/// CF-Ray：合规值进日志，不合规值被丢弃；不影响响应。
#[tokio::test]
async fn cf_ray_logged_only_when_valid() {
    install_capture();
    let Some(app) = common::setup(|_| {}).await else {
        return;
    };

    // 每次请求用带随机后缀的唯一路径（404 没关系），并行测试互不干扰
    let ok_path = format!("/cf-ray-marker-{}", uuid::Uuid::new_v4().simple());
    let response = app
        .client
        .get(app.url(&ok_path))
        .header("CF-Ray", "8f1e2d3e4f5a6b7c")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    let line = access_line_for(&ok_path);
    assert!(!line.is_empty(), "没找到 {ok_path} 的日志行");
    assert!(line.contains("cf_ray"), "合规 CF-Ray 应记入日志：{line}");
    assert!(line.contains("8f1e2d3e4f5a6b7c"), "{line}");

    // 不合法：含空格与注入字符 → 丢弃，不出现 cf_ray 字段
    let bad_path = format!("/cf-ray-marker-{}", uuid::Uuid::new_v4().simple());
    let response = app
        .client
        .get(app.url(&bad_path))
        .header("CF-Ray", "bad ray; injection")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    let line = access_line_for(&bad_path);
    assert!(!line.is_empty(), "没找到 {bad_path} 的日志行");
    assert!(!line.contains("cf_ray"), "不合规 CF-Ray 必须被丢弃：{line}");
    assert!(line.contains("request_id"), "request_id 照常记录：{line}");

    // 超长同样丢弃
    let long_path = format!("/cf-ray-marker-{}", uuid::Uuid::new_v4().simple());
    let response = app
        .client
        .get(app.url(&long_path))
        .header("CF-Ray", "a".repeat(41))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    assert!(
        !access_line_for(&long_path).contains("cf_ray"),
        "超长 CF-Ray 必须被丢弃"
    );
}
