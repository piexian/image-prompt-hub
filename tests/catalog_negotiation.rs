//! /v1/catalog 的 Accept-Encoding 协商、双 ETag 变体与 304/HEAD 行为。

mod common;

use common::TestApp;

fn gunzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(bytes);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).expect("解压失败");
    out
}

fn etag_hash(etag: &str) -> &str {
    etag.trim_start_matches("W/").trim_matches('"')
}

#[tokio::test]
async fn catalog_negotiates_encoding_and_etag_variants() {
    let Some(app) = common::setup(|_| {}).await else {
        return;
    };
    let url = app.url("/v1/catalog");

    // 不声明 / identity / gzip;q=0 / *;q=0 → 明文 JSON、弱 ETag、无 CE、有 Vary
    for header in ["identity", "gzip;q=0", "*;q=0", "gzip;q=abc"] {
        let response = app
            .client
            .get(&url)
            .header("Accept-Encoding", header)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "AE={header}");
        assert!(
            response.headers().get("content-encoding").is_none(),
            "AE={header} 不应压缩"
        );
        let etag = response.headers()["etag"].to_str().unwrap().to_string();
        assert!(etag.starts_with("W/\""), "AE={header} 应用弱 ETag：{etag}");
        assert_eq!(response.headers()["vary"], "Accept-Encoding", "AE={header}");
        let body = response.bytes().await.unwrap();
        let plain: serde_json::Value = serde_json::from_slice(&body).expect("明文应是合法 JSON");
        assert_eq!(plain["format"], "gemini-image-templates");
    }
    // reqwest 默认不发 Accept-Encoding（gzip feature 未开）；无头同样明文
    let no_header = app.client.get(&url).send().await.unwrap();
    assert!(no_header.headers().get("content-encoding").is_none());
    assert!(no_header.headers()["etag"]
        .to_str()
        .unwrap()
        .starts_with("W/\""));

    // gzip / 多编码 / 通配符 → gzip 字节、强 ETag
    let mut strong_etag = String::new();
    let mut plain_bytes = Vec::new();
    for header in ["gzip", "GZIP", "gzip, deflate, br", "*", "gzip;q=0.5"] {
        let response = app
            .client
            .get(&url)
            .header("Accept-Encoding", header)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "AE={header}");
        assert_eq!(
            response.headers()["content-encoding"],
            "gzip",
            "AE={header}"
        );
        let etag = response.headers()["etag"].to_str().unwrap().to_string();
        assert!(
            !etag.starts_with("W/") && etag.starts_with('"'),
            "AE={header} 应用强 ETag：{etag}"
        );
        assert_eq!(response.headers()["vary"], "Accept-Encoding", "AE={header}");
        let body = response.bytes().await.unwrap().to_vec();
        let decompressed = gunzip(&body);
        if plain_bytes.is_empty() {
            plain_bytes = decompressed.clone();
        } else {
            assert_eq!(decompressed, plain_bytes, "各请求解压后内容一致");
        }
        if strong_etag.is_empty() {
            strong_etag = etag;
        } else {
            assert_eq!(etag, strong_etag, "gzip 变体的强 ETag 稳定");
        }
    }

    // 明文弱 ETag 与 gzip 强 ETag 的哈希部分一致（同一份内容）
    let weak_etag = {
        let response = app
            .client
            .get(&url)
            .header("Accept-Encoding", "identity")
            .send()
            .await
            .unwrap();
        response.headers()["etag"].to_str().unwrap().to_string()
    };
    assert_eq!(etag_hash(&weak_etag), etag_hash(&strong_etag));

    // If-None-Match 弱比较：强弱形式 × 两种变体都命中 304，且带 ETag 与 Vary
    for (sent, accept) in [
        (strong_etag.clone(), "gzip"),
        (strong_etag.clone(), "identity"),
        (weak_etag.clone(), "gzip"),
        (weak_etag.clone(), "identity"),
    ] {
        let response = app
            .client
            .get(&url)
            .header("Accept-Encoding", accept)
            .header("If-None-Match", &sent)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 304, "If-None-Match={sent} AE={accept}");
        assert!(response.headers().contains_key("etag"), "304 应带 ETag");
        assert_eq!(
            response.headers()["vary"],
            "Accept-Encoding",
            "304 应带 Vary"
        );
        let body = response.bytes().await.unwrap();
        assert!(body.is_empty(), "304 不应有正文");
    }

    // HEAD：头齐全、无正文
    let head = app
        .client
        .head(&url)
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 200);
    assert_eq!(head.headers()["content-encoding"], "gzip");
    assert_eq!(head.headers()["etag"], strong_etag);
    assert_eq!(head.headers()["vary"], "Accept-Encoding");
    let body = head.bytes().await.unwrap();
    assert!(body.is_empty(), "HEAD 不应有正文");
}

/// 快照内容变化后：两种变体的 ETag 哈希一起变化且保持一致。
#[tokio::test]
async fn etag_hash_tracks_content_for_both_variants() {
    let Some(app) = common::setup(|config| config.catalog_debounce_secs = 0).await else {
        return;
    };
    let key = app
        .create_key_direct("nego@qq.com", &["read", "write"])
        .await;

    let before = app.catalog_etag_hash("gzip").await;
    let created = app
        .client
        .post(app.url("/v1/templates"))
        .bearer_auth(&key)
        .json(&serde_json::json!({"name": "协商", "content": "内容 {{input}}"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);

    app.wait_catalog_hash_changes(&before).await;
    let after_gzip = app.catalog_etag_hash("gzip").await;
    let after_plain = app.catalog_etag_hash("identity").await;
    assert_ne!(after_gzip, before, "gzip 变体哈希应随内容变化");
    assert_eq!(after_gzip, after_plain, "两种变体的哈希部分一致");
}

impl TestApp {
    /// 取当前快照在指定编码变体下的 ETag 哈希部分。
    async fn catalog_etag_hash(&self, accept: &str) -> String {
        let response = self
            .client
            .get(self.url("/v1/catalog"))
            .header("Accept-Encoding", accept)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        etag_hash(response.headers()["etag"].to_str().unwrap()).to_string()
    }
}
