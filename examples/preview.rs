//! 开发用预览：把三种邮件与页面样例的 HTML 写到 target/preview/，
//! 在浏览器里直接打开 .html 查看效果。不进正式二进制。

use image_prompt_hub::api::public::StatusResponse;
use image_prompt_hub::catalog::CatalogMeta;
use image_prompt_hub::email::templates::{api_key_email, verification_email, EmailContent};
use image_prompt_hub::pages::{page, status_page, PageKind};

const BASE: &str = "https://hub.example.com";

fn sample_status(with_catalog: bool) -> StatusResponse {
    let generated_at = chrono::DateTime::parse_from_rfc3339("2026-10-31T14:13:09Z")
        .expect("样例时间可解析")
        .with_timezone(&chrono::Utc);
    StatusResponse {
        version: "0.1.0".to_string(),
        template_count: 30,
        catalog: with_catalog.then(|| CatalogMeta {
            hash: "7be5040b6c82f1349f8a71f2aae9db776dd828da60d2cbc4f595d0bf8161ebe4".to_string(),
            count: 30,
            updated_at: "2026-10-31T14:13:09Z".to_string(),
            size: 7874,
        }),
        rate_limits: serde_json::json!({
            "anonymous_read_per_minute_per_ip": 60,
            "keyed_read_per_minute_per_key": 600,
            "write_per_minute_per_key": 60,
            "key_request_per_hour_per_ip": 5,
            "key_verify_per_hour_per_ip": 20,
            "report_per_hour_per_ip": 10,
            "auth_failure_per_minute_per_ip": 30,
            "account_create_per_hour": 100,
            "account_template_limit": 1000,
        }),
        generated_at,
    }
}

fn main() {
    let dir = std::path::Path::new("target/preview/emails");
    std::fs::create_dir_all(dir).expect("创建预览目录失败");

    let previews: [(&str, EmailContent); 3] = [
        (
            "verification-issue",
            verification_email(
                "issue",
                &format!("{BASE}/v1/keys/verify?token=example-issue-token"),
            ),
        ),
        (
            "verification-reset",
            verification_email(
                "reset",
                &format!("{BASE}/v1/keys/verify?token=example-reset-token"),
            ),
        ),
        (
            "api-key",
            api_key_email(
                "iph_examplekeydo-not-use-0000000000000000",
                &format!("{BASE}/v1/keys/revoke?token=example-revoke-token"),
            ),
        ),
    ];

    for (name, mail) in previews {
        let html_path = dir.join(format!("{name}.html"));
        let text_path = dir.join(format!("{name}.txt"));
        std::fs::write(&html_path, &mail.html).expect("写入 HTML 预览失败");
        std::fs::write(&text_path, &mail.text).expect("写入纯文本预览失败");
        println!("已写入 {}", html_path.display());
    }
    println!("在浏览器中打开 target/preview/emails/*.html 查看效果");

    // 页面预览：确认页、导航页，以及状态页的有快照 / 无快照两种
    let page_dir = std::path::Path::new("target/preview/pages");
    std::fs::create_dir_all(page_dir).expect("创建页面预览目录失败");
    let verify_form = "<p>你正在为这个邮箱申请 API 密钥。</p>\
        <form method=\"post\" action=\"/v1/keys/verify\">\
        <input type=\"hidden\" name=\"token\" value=\"example-token\">\
        <button type=\"submit\">确认</button></form>\
        <p class=\"muted\">不是你本人的操作？直接关闭本页即可。</p>";
    let revoke_form = "<p>即将吊销密钥 <span class=\"ktag\">iph_exampleprefix</span>。</p>\
        <p>吊销后使用这把密钥的插件会立刻失效。</p>\
        <p>之后可以用同一个邮箱重新申请新密钥。</p>\
        <form method=\"post\" action=\"/v1/keys/revoke\">\
        <input type=\"hidden\" name=\"token\" value=\"example-token\">\
        <button type=\"submit\">确认吊销</button></form>";
    let pages: [(&str, String); 10] = [
        ("verify-confirm", page(PageKind::Confirm, "确认操作", "确认申请密钥", verify_form)),
        ("revoke-confirm", page(PageKind::Confirm, "确认吊销", "确认吊销密钥", revoke_form)),
        (
            "key-sent",
            page(PageKind::Success, "操作完成", "密钥已发送到邮箱", "<p>请到邮箱查收密钥邮件。没有收到时，检查垃圾邮件文件夹。</p>"),
        ),
        (
            "key-revoked",
            page(PageKind::Success, "已吊销", "密钥已吊销", "<p>使用这把密钥的插件会立刻失效。需要新密钥时，用同一个邮箱重新申请即可。</p>"),
        ),
        (
            "banned",
            page(PageKind::Warning, "无法发放", "无法为这个邮箱发放密钥", "<p>如有疑问请联系管理员。</p>"),
        ),
        (
            "daily-limit",
            page(PageKind::Warning, "发送受限", "今日发信已达上限", "<p>大约 4 小时后请重新打开邮件里的链接再点一次“确认”。</p>"),
        ),
        (
            "invalid-link",
            page(PageKind::Error, "链接无效", "链接无效或已过期", "<p>这个验证链接不存在、已被使用或已超过 30 分钟有效期。请重新申请密钥。</p>"),
        ),
        (
            "index",
            page(
                PageKind::Info,
                "image-prompt-hub",
                "image-prompt-hub",
                "<p>AstrBot 图片生成插件配套的在线提示词模板服务：公开检索与下载，申请密钥后可上传。</p>\
                 <div class=\"btn-grid\">\
                 <a class=\"btn\" href=\"/llms.txt\">接口说明（llms.txt）</a>\
                 <a class=\"btn-secondary\" href=\"/openapi.json\">OpenAPI 文档</a>\
                 <a class=\"btn-secondary\" href=\"/status\">服务状态</a>\
                 <a class=\"btn-secondary\" href=\"/v1/catalog/version\">目录快照版本</a>\
                 </div>\
                 <p class=\"muted\">如何申请密钥：在 AstrBot 图片生成插件的提示词广场“在线”页里填写邮箱申请，验证邮件里点确认即可。</p>",
            ),
        ),
        (
            "status-ok",
            status_page(&sample_status(true)),
        ),
        (
            "status-no-snapshot",
            status_page(&sample_status(false)),
        ),
    ];
    for (name, html) in pages {
        let path = page_dir.join(format!("{name}.html"));
        std::fs::write(&path, html).expect("写入页面预览失败");
        println!("已写入 {}", path.display());
    }
    println!("在浏览器中打开 target/preview/pages/*.html 查看页面效果");
}
