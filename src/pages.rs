//! 确认类页面与根路径导航页：统一视觉的纯 HTML 输出。
//! 只用内联 `<style>` 与内联 SVG，不放宽 CSP，不引入脚本与外部资源。

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};

use crate::html::escape_html;

/// 源代码仓库地址（部署前暂不可访问，属预期）。
pub const SOURCE_URL: &str = "https://github.com/piexian/image-prompt-hub";

/// 页面类别：决定图标徽章的强调色与图形。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageKind {
    /// 需要用户确认的操作，紫色。
    Confirm,
    /// 操作成功，薄荷绿。
    Success,
    /// 提醒与受限，柠檬黄。
    Warning,
    /// 失败与无效，珊瑚红。
    Error,
    /// 一般信息，紫色。
    Info,
}

impl PageKind {
    /// 徽章底色。
    fn badge_bg(self) -> &'static str {
        match self {
            Self::Confirm | Self::Info => "#6C5CE7",
            Self::Success => "#00B894",
            Self::Warning => "#FFC93C",
            Self::Error => "#F76707",
        }
    }

    /// 徽章里的描边图标颜色，与底色保持足够对比。
    fn icon_color(self) -> &'static str {
        match self {
            Self::Confirm | Self::Info => "#FFFFFF",
            Self::Success => "#073B2C",
            Self::Warning => "#6B5518",
            Self::Error => "#FFFFFF",
        }
    }

    /// 简洁描边图标（24×24，随类别更换）。
    fn icon_svg(self) -> &'static str {
        match self {
            // 钥匙
            Self::Confirm | Self::Info => {
                r#"<svg aria-hidden="true" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="__COLOR__" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="12" r="3.5"/><path d="M11.5 12H20M17 12v3.5M20 12v2.5"/></svg>"#
            }
            // 对勾
            Self::Success => {
                r#"<svg aria-hidden="true" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="__COLOR__" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 12.5l5 5 10-11"/></svg>"#
            }
            // 感叹号三角
            Self::Warning => {
                r#"<svg aria-hidden="true" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="__COLOR__" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4L2.5 20h19L12 4z"/><path d="M12 10v4.5"/><path d="M12 17.2v.1"/></svg>"#
            }
            // 叉号
            Self::Error => {
                r#"<svg aria-hidden="true" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="__COLOR__" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>"#
            }
        }
    }
}

/// 组装整页 HTML：渐变色带、压住色带的卡片、图标徽章、标题、正文与页脚。
/// `heading` 与 `body_html` 里的动态值由调用方负责转义。
pub fn page(kind: PageKind, title: &str, heading: &str, body_html: &str) -> String {
    let icon = kind.icon_svg().replace("__COLOR__", kind.icon_color());
    format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
:root {{ color-scheme: light dark; }}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; min-height: 100vh;
  background-color: #F4F1FF; color: #2D2A4A;
  font-family: -apple-system,'PingFang SC','Microsoft YaHei','Segoe UI',Arial,sans-serif;
  line-height: 1.65;
}}
.band {{
  background-color: #6C5CE7;
  background-image: linear-gradient(135deg,#6C5CE7,#FD79A8);
  padding: 26px 24px 56px; text-align: center;
}}
.band .brand {{ display: block; color: #ffffff; font-weight: 700; font-size: 20px; }}
.band .sub {{ display: block; margin-top: 4px; color: #ffffff; font-size: 13px; }}
.dots {{ display: inline-flex; gap: 7px; margin-top: 12px; }}
.dots i {{ width: 9px; height: 9px; border-radius: 999px; }}
.dots i:nth-child(1) {{ background-color: #FD79A8; }}
.dots i:nth-child(2) {{ background-color: #FFC93C; }}
.dots i:nth-child(3) {{ background-color: #00B894; }}
main.card {{
  width: min(100%, 520px);
  margin: -36px auto 0; padding: 8px 28px 26px;
  background-color: #ffffff; border-radius: 20px;
  box-shadow: 0 10px 32px rgba(45,42,74,.14);
  text-align: center;
}}
.badge {{
  width: 64px; height: 64px; border-radius: 999px;
  display: flex; align-items: center; justify-content: center;
  margin: 8px auto 6px; background-color: {badge};
}}
h1 {{ margin: 10px 0 12px; font-size: 22px; font-weight: 700; color: #2D2A4A; }}
main.card p {{ margin: 8px 0; font-size: 15px; }}
main.card p.muted {{ color: #6B6885; font-size: 13px; }}
.ktag {{
  display: inline-block; padding: 2px 10px; border-radius: 8px;
  background-color: #F4F1FF; color: #2D2A4A;
  font-family: 'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;
  font-size: 14px; word-break: break-all;
}}
form {{ margin: 16px 0 4px; }}
button, a.btn {{
  display: inline-block; margin: 6px 4px; padding: 12px 34px;
  border: none; border-radius: 999px; cursor: pointer;
  background-color: #F76707; color: #ffffff;
  font-size: 16px; font-weight: 700; text-decoration: none;
  transition: filter .15s ease, transform .05s ease;
}}
a.btn-secondary {{
  display: inline-block; margin: 6px 4px; padding: 10px 28px;
  border: 2px solid #6C5CE7; border-radius: 999px;
  background-color: transparent; color: #6C5CE7;
  font-size: 15px; font-weight: 600; text-decoration: none;
  transition: background-color .15s ease;
}}
button:hover, a.btn:hover {{ filter: brightness(1.06); }}
button:active, a.btn:active {{ transform: translateY(1px); }}
button:focus-visible, a.btn:focus-visible, a.btn-secondary:focus-visible, a:focus-visible {{
  outline: 3px solid #6C5CE7; outline-offset: 2px;
}}
a.btn-secondary:hover {{ background-color: #F4F1FF; }}
/* 导航页按钮组：2x2 等宽网格，窄屏收成一列。
   格内按钮统一为 flex 垂直居中、等高与同字号，主按钮不撑高同行。 */
.btn-grid {{
  display: grid; grid-template-columns: 1fr 1fr; gap: 10px;
  margin: 16px 0 4px;
}}
.btn-grid a {{
  display: flex; align-items: center; justify-content: center;
  text-align: center; min-height: 48px; padding: 10px 16px;
  margin: 0; font-size: 15px;
}}
.pagefoot {{
  margin: 18px 0 26px; text-align: center;
  color: #6B6885; font-size: 12px;
}}
.pagefoot a {{ color: #6B6885; }}
/* 窄屏：卡片两侧留边，避免贴满屏幕；内边距同步收窄 */
@media (max-width: 560px) {{
  main.card {{ width: auto; margin: -36px 12px 0; padding: 8px 16px 22px; }}
  .btn-grid {{ grid-template-columns: 1fr; }}
}}
@media (prefers-color-scheme: dark) {{
  body {{ background-color: #14121F; color: #ECEAF7; }}
  main.card {{ background-color: #1F1B2E; box-shadow: 0 10px 32px rgba(0,0,0,.5); }}
  h1 {{ color: #ECEAF7; }}
  main.card p {{ color: #ECEAF7; }}
  main.card p.muted {{ color: #A9A5C6; }}
  .ktag {{ background-color: #2A2440; color: #ECEAF7; }}
  a.btn-secondary {{ border-color: #9C93F0; color: #B9B1F5; }}
  a.btn-secondary:hover {{ background-color: #2A2440; }}
  .pagefoot, .pagefoot a {{ color: #A9A5C6; }}
}}
@media (prefers-reduced-motion: reduce) {{
  * {{ transition: none !important; }}
}}
</style>
</head>
<body>
<header class="band">
  <span class="brand">image-prompt-hub</span>
  <span class="sub">AstrBot 图片生成插件 · 在线提示词模板库</span>
  <span class="dots" aria-hidden="true"><i></i><i></i><i></i></span>
</header>
<main class="card">
  <div class="badge">{icon}</div>
  <h1>{heading}</h1>
  {body}
</main>
<footer class="pagefoot">image-prompt-hub · 开源提示词模板服务 · <a href="{source}">源代码</a></footer>
</body>
</html>"#,
        title = escape_html(title),
        badge = kind.badge_bg(),
        heading = escape_html(heading),
        body = body_html,
        source = SOURCE_URL,
    )
}

/// 页面响应：统一安全头，一律 no-store（确认页含令牌，禁止任何缓存）。
pub fn html_response(body: String, status: StatusCode) -> Response {
    let mut response = Html(body).into_response();
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
        ),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// 根路径导航页：静态 HTML，不查库、不限流。
pub async fn index() -> Response {
    let body = "<p>AstrBot 图片生成插件配套的在线提示词模板服务：公开检索与下载，申请密钥后可上传。</p>\
        <div class=\"btn-grid\">\
        <a class=\"btn\" href=\"/llms.txt\">接口说明（llms.txt）</a>\
        <a class=\"btn-secondary\" href=\"/openapi.json\">OpenAPI 文档</a>\
        <a class=\"btn-secondary\" href=\"/v1/status\">服务状态</a>\
        <a class=\"btn-secondary\" href=\"/v1/catalog/version\">目录快照版本</a>\
        </div>\
        <p class=\"muted\">如何申请密钥：在 AstrBot 图片生成插件的提示词广场“在线”页里填写邮箱申请，验证邮件里点确认即可。</p>";
    html_response(
        page(PageKind::Info, "image-prompt-hub", "image-prompt-hub", body),
        StatusCode::OK,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 每种类别各渲染一页，覆盖全部图标与强调色。
    fn sample_pages() -> Vec<(&'static str, String)> {
        vec![
            (
                "confirm-verify",
                page(
                    PageKind::Confirm,
                    "确认操作",
                    "确认申请密钥",
                    "<p>你正在为这个邮箱申请 API 密钥。</p><form method=\"post\" action=\"/v1/keys/verify\"><input type=\"hidden\" name=\"token\" value=\"tok\"><button type=\"submit\">确认</button></form>",
                ),
            ),
            (
                "confirm-revoke",
                page(
                    PageKind::Confirm,
                    "确认吊销",
                    "确认吊销密钥",
                    "<p>即将吊销密钥 <span class=\"ktag\">iph_example</span>。</p><form method=\"post\" action=\"/v1/keys/revoke\"><button type=\"submit\">确认吊销</button></form>",
                ),
            ),
            (
                "success-key-sent",
                page(PageKind::Success, "操作完成", "密钥已发送到邮箱", "<p>请到邮箱查收密钥邮件。</p>"),
            ),
            (
                "success-revoked",
                page(PageKind::Success, "已吊销", "密钥已吊销", "<p>使用这把密钥的插件会立刻失效。</p>"),
            ),
            (
                "warning-rate-limited",
                page(PageKind::Warning, "发送受限", "今日发信已达上限", "<p>请稍后重试。</p>"),
            ),
            (
                "error-invalid",
                page(PageKind::Error, "链接无效", "链接无效或已过期", "<p>请重新申请密钥。</p>"),
            ),
            (
                "info-index",
                page(
                    PageKind::Info,
                    "image-prompt-hub",
                    "image-prompt-hub",
                    "<p><a class=\"btn\" href=\"/llms.txt\">接口说明（llms.txt）</a></p>",
                ),
            ),
        ]
    }

    #[test]
    fn all_pages_well_formed_and_safe() {
        for (name, html) in sample_pages() {
            assert!(
                crate::html::tests::attribute_problems(&html).is_empty(),
                "{name} 属性良构检查失败"
            );
            assert!(html.contains("lang=\"zh-CN\""), "{name}");
            assert!(html.contains("viewport"), "{name}");
            assert!(
                html.contains("@media (prefers-color-scheme: dark)"),
                "{name}"
            );
            assert!(
                html.contains("@media (prefers-reduced-motion: reduce)"),
                "{name}"
            );
            assert!(html.contains("<main"), "{name}");
            assert!(!html.contains("<script"), "{name} 不允许脚本");
            assert!(!html.contains("src="), "{name} 不允许资源引用");
            assert!(!html.contains("@import"), "{name}");
            assert!(!html.contains("url(http"), "{name}");
            // 图标徽章与页脚
            assert!(
                html.contains("aria-hidden=\"true\""),
                "{name} SVG 需 aria-hidden"
            );
            assert!(html.contains("源代码"), "{name} 页脚");
            assert!(html.contains(SOURCE_URL), "{name} 源代码链接");
            assert!(
                html.contains("AstrBot 图片生成插件 · 在线提示词模板库"),
                "{name}"
            );
            assert!(
                html.len() <= 20 * 1024,
                "{name} 页面应在 20KB 内：{} 字节",
                html.len()
            );
        }
    }

    #[test]
    fn each_kind_has_own_badge_and_icon() {
        let cases = [
            (PageKind::Confirm, "#6C5CE7"),
            (PageKind::Info, "#6C5CE7"),
            (PageKind::Success, "#00B894"),
            (PageKind::Warning, "#FFC93C"),
            (PageKind::Error, "#F76707"),
        ];
        for (kind, bg) in cases {
            let html = page(kind, "t", "标题", "<p>x</p>");
            assert!(
                html.contains(&format!("background-color: {bg}")),
                "{kind:?}"
            );
            assert!(html.contains("<svg"), "{kind:?} 必须有内联图标");
        }
        // 图标之间确有差异（钥匙/对勾/三角/叉）
        let confirm = page(PageKind::Confirm, "t", "h", "");
        let success = page(PageKind::Success, "t", "h", "");
        assert_ne!(confirm.matches('<').count(), 0);
        assert!(confirm.contains("<circle cx=\"8\" cy=\"12\" r=\"3.5\"/>"));
        assert!(success.contains("<path d=\"M4.5 12.5l5 5 10-11\"/>"));
    }

    #[test]
    fn dynamic_values_are_escaped() {
        let html = page(
            PageKind::Error,
            "标题<script>",
            "标题<script>",
            "<p>内容</p>",
        );
        assert!(html.contains("标题&lt;script&gt;"));
        assert!(!html.contains("标题<script>"), "动态值必须转义");
        assert!(html.contains("<title>标题&lt;script&gt;</title>"));
    }

    #[tokio::test]
    async fn index_page_contains_navigation() {
        let response = index().await;
        assert_eq!(response.status(), 200);
        let headers = response.headers().clone();
        for header in [
            "content-security-policy",
            "x-frame-options",
            "cache-control",
            "referrer-policy",
        ] {
            assert!(headers.contains_key(header), "缺少 {header}");
        }
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();
        for link in [
            "/llms.txt",
            "/openapi.json",
            "/v1/status",
            "/v1/catalog/version",
        ] {
            assert!(
                html.contains(&format!("href=\"{link}\"")),
                "缺少导航 {link}"
            );
        }
        assert!(html.contains("公开检索与下载，申请密钥后可上传"));
        assert!(html.contains("如何申请密钥"));
    }
}
