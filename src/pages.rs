//! 确认类页面、根路径导航页与服务状态页：统一视觉的纯 HTML 输出。
//! 只用内联 `<style>` 与内联 SVG，不放宽 CSP，不引入脚本与外部资源。

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};

use crate::api::public::StatusResponse;
use crate::catalog::CatalogMeta;
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
    // 现有页面保持 520px；宽卡片只给信息更密的状态页，避免改动其他页面的 HTML。
    render_page(kind, title, heading, body_html, false, "")
}

fn render_page(
    kind: PageKind,
    title: &str,
    heading: &str,
    body_html: &str,
    wide: bool,
    extra_css: &str,
) -> String {
    let icon = kind.icon_svg().replace("__COLOR__", kind.icon_color());
    let card_width = if wide { "720px" } else { "520px" };
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
  width: min(100%, {card_width});
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
{extra_css}</style>
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
        card_width = card_width,
        extra_css = extra_css,
        title = escape_html(title),
        badge = kind.badge_bg(),
        heading = escape_html(heading),
        body = body_html,
        source = SOURCE_URL,
    )
}

/// 状态页专用样式。只拼进这一页，其他页面的样式表保持原样。
const STATUS_CSS: &str = r#"
h2 { margin: 18px 0 8px; font-size: 15px; text-align: left; color: #2D2A4A; }
.tiles { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin: 4px 0 8px; }
.tile { background-color: #F4F1FF; border-radius: 14px; padding: 12px 10px; text-align: center; }
.tile .label, .tile .note { color: #6B6885; font-size: 12px; word-break: break-all; }
.tile .num { margin: 2px 0; color: #2D2A4A; font-size: 28px; font-weight: 700; line-height: 1.2; word-break: break-all; }
.lines { text-align: left; }
.line { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 8px 0; border-bottom: 1px solid #E6E1F5; font-size: 14px; }
.name { display: inline-flex; align-items: center; gap: 8px; }
.dot { width: 8px; height: 8px; border-radius: 999px; background-color: #00B894; }
.dot.wait { background-color: #FFC93C; }
dl { margin: 0; text-align: left; }
dl div { display: grid; grid-template-columns: 5.5em 1fr; gap: 8px; padding: 8px 0; border-bottom: 1px solid #E6E1F5; font-size: 14px; }
dt { color: #6B6885; }
dd { margin: 0; word-break: break-all; }
.mono { font-family: 'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace; font-size: 13px; }
table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }
th, td { padding: 8px 0; border-bottom: 1px solid #E6E1F5; font-weight: 400; vertical-align: top; }
th { color: #6B6885; font-size: 12px; }
td:last-child, th:last-child { text-align: right; }
.btn-grid { grid-template-columns: repeat(3, 1fr); }
p.gap { margin-top: 16px; }
@media (max-width: 560px) {
  .tile { padding: 10px 6px; }
  .tile .num { font-size: 22px; }
  .tile .label, .tile .note { font-size: 11px; }
  .btn-grid { grid-template-columns: 1fr; }
}
@media (prefers-color-scheme: dark) {
  h2, .tile .num { color: #ECEAF7; }
  .tile { background-color: #2A2440; }
  .tile .label, .tile .note, dt, th { color: #A9A5C6; }
  .line, dl div, th, td { border-bottom-color: #3A3454; }
}
"#;

/// 服务状态页。纯函数：数据进、HTML 出，便于单测和预览。
pub fn status_page(status: &StatusResponse) -> String {
    let generated_attr = escape_html(&rfc3339_utc(status.generated_at));
    let generated_text = escape_html(&format_beijing(status.generated_at));
    let version = escape_html(&status.version);
    let snapshot = snapshot_view(status.catalog.as_ref());
    let limits = rate_limit_rows(&status.rate_limits);
    // 能渲染到这里说明数据库查询已经成功，所以这一行固定为正常。
    let body = format!(
        r#"<p class="muted">状态生成于 <time datetime="{generated_attr}">{generated_text}</time>（北京时间）</p>
<div class="tiles">
<div class="tile"><div class="label">已公开模板</div><div class="num">{count}</div><div class="note">条</div></div>
<div class="tile"><div class="label">目录快照</div><div class="num">{snap_num}</div><div class="note">{snap_note}</div></div>
<div class="tile"><div class="label">服务版本</div><div class="num">{version}</div><div class="note">AGPL-3.0 开源</div></div>
</div>
<h2>运行状况</h2>
<div class="lines">
<div class="line"><span class="name"><span class="dot" aria-hidden="true"></span>数据库</span><span>正常</span></div>
<div class="line"><span class="name"><span class="dot {dot}" aria-hidden="true"></span>目录快照</span><span>{state}</span></div>
</div>
<h2>目录快照</h2>
{section}
<h2>访问限制</h2>
<table>
<thead><tr><th>名称</th><th>额度</th></tr></thead>
<tbody>
{limits}</tbody>
</table>
<p class="muted gap">程序读取状态请用 /v1/status，返回 JSON，不受本页影响。</p>
<div class="btn-grid">
<a class="btn" href="/">返回首页</a>
<a class="btn-secondary" href="/llms.txt">接口说明</a>
<a class="btn-secondary" href="/v1/status">JSON 版本</a>
</div>"#,
        count = status.template_count,
        snap_num = snapshot.num,
        snap_note = snapshot.note,
        dot = snapshot.dot,
        state = snapshot.state,
        section = snapshot.section,
        limits = limits,
    );
    render_page(
        PageKind::Success,
        "服务状态",
        "服务运行正常",
        &body,
        true,
        STATUS_CSS,
    )
}

struct SnapshotView {
    num: String,
    note: String,
    section: String,
    dot: &'static str,
    state: &'static str,
}

fn snapshot_view(meta: Option<&CatalogMeta>) -> SnapshotView {
    match meta {
        Some(meta) => {
            let prefix: String = meta.hash.chars().take(8).collect();
            SnapshotView {
                num: escape_html(&format_bytes(meta.size)),
                note: escape_html(&format!("哈希 {prefix}…")),
                section: catalog_details(meta),
                dot: "ok",
                state: "已就绪",
            }
        }
        None => SnapshotView {
            num: "—".to_string(),
            note: "生成中".to_string(),
            section: r#"<p class="muted">快照还在生成中，稍后刷新本页</p>"#.to_string(),
            dot: "wait",
            state: "生成中",
        },
    }
}

fn catalog_details(meta: &CatalogMeta) -> String {
    format!(
        r#"<dl>
<div><dt>哈希</dt><dd class="mono">{hash}</dd></div>
<div><dt>模板数</dt><dd>{count}</dd></div>
<div><dt>大小</dt><dd>{size}</dd></div>
<div><dt>最近更新</dt><dd>{updated}</dd></div>
</dl>"#,
        hash = escape_html(&meta.hash),
        count = meta.count,
        size = escape_html(&format_bytes(meta.size)),
        updated = catalog_updated(&meta.updated_at),
    )
}

fn catalog_updated(raw: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(raw) {
        Ok(parsed) => {
            let utc = parsed.with_timezone(&chrono::Utc);
            format!(
                "<time datetime=\"{}\">{}</time>",
                escape_html(&rfc3339_utc(utc)),
                escape_html(&format_beijing(utc))
            )
        }
        Err(_) => escape_html(raw),
    }
}

/// 1024 进制。不足 1KB 用字节整数，其上保留一位小数。
fn format_bytes(bytes: u64) -> String {
    const STEP: f64 = 1024.0;
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while unit + 1 < UNITS.len() && value >= STEP {
        value /= STEP;
        unit += 1;
    }
    // 一位小数四舍五入后会写成 1024.0，再进一档才是下一级的 1.0。
    if unit + 1 < UNITS.len() && (value * 10.0).round() >= STEP * 10.0 {
        value /= STEP;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// 北京时间固定 UTC+8，不引入时区数据库。
fn format_beijing(utc: chrono::DateTime<chrono::Utc>) -> String {
    let offset = chrono::FixedOffset::east_opt(8 * 3600).expect("UTC+8 在合法偏移范围内");
    utc.with_timezone(&offset)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

fn rfc3339_utc(utc: chrono::DateTime<chrono::Utc>) -> String {
    utc.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

const RATE_ROWS: &[(&str, &str, &str)] = &[
    ("anonymous_read_per_minute_per_ip", "匿名读取", "次/分钟/IP"),
    (
        "keyed_read_per_minute_per_key",
        "带密钥读取",
        "次/分钟/密钥",
    ),
    (
        "write_per_minute_per_key",
        "上传、修改、删除",
        "次/分钟/密钥",
    ),
    ("key_request_per_hour_per_ip", "申请密钥", "次/小时/IP"),
    ("key_verify_per_hour_per_ip", "邮件链接确认", "次/小时/IP"),
    ("report_per_hour_per_ip", "举报", "次/小时/IP"),
    ("auth_failure_per_minute_per_ip", "认证失败", "次/分钟/IP"),
    (
        "account_create_per_hour",
        "每个账号每小时新建模板",
        "条/小时",
    ),
    ("account_template_limit", "每个账号的模板总数上限", "条"),
];

fn rate_limit_rows(limits: &serde_json::Value) -> String {
    let mut html = String::new();
    for (key, name, unit) in RATE_ROWS {
        let value = match limits.get(*key).and_then(json_u64) {
            Some(n) => escape_html(&format!("{n} {unit}")),
            None => "—".to_string(),
        };
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td></tr>\n",
            escape_html(name),
            value
        ));
    }
    html
}

fn json_u64(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|n| u64::try_from(n).ok()))
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
        <a class=\"btn-secondary\" href=\"/status\">服务状态</a>\
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
            assert!(html.contains("min(100%, 520px)"), "{name} 应保持窄卡片");
            assert!(!html.contains("720px"), "{name} 不应使用宽卡片");
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
            "/status",
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
    fn fixed_time() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-10-31T14:13:09Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn fixed_status(with_catalog: bool) -> StatusResponse {
        const HASH: &str = "7be5040b6c82f1349f8a71f2aae9db776dd828da60d2cbc4f595d0bf8161ebe4";
        StatusResponse {
            version: "0.1.0".to_string(),
            template_count: 30,
            catalog: with_catalog.then(|| CatalogMeta {
                hash: HASH.to_string(),
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
            generated_at: fixed_time(),
        }
    }

    #[test]
    fn format_bytes_and_beijing_time() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(7874), "7.7 KB");
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
        assert_eq!(format_beijing(fixed_time()), "2026-10-31 22:13:09");
    }

    #[test]
    fn status_page_renders_snapshot_limits_and_time() {
        const HASH: &str = "7be5040b6c82f1349f8a71f2aae9db776dd828da60d2cbc4f595d0bf8161ebe4";
        let html = status_page(&fixed_status(true));
        assert!(html.contains("服务运行正常"));
        assert!(html.contains("class=\"num\">30<"));
        assert!(html.contains("class=\"num\">0.1.0<"));
        assert!(html.contains("class=\"num\">7.7 KB<"));
        assert_eq!(html.matches(HASH).count(), 1, "完整哈希应出现一次");
        assert!(html.contains("哈希 7be5040b…"));
        assert!(html.contains("2026-10-31 22:13:09"));
        assert!(html.contains("datetime=\"2026-10-31T14:13:09Z\""));
        assert!(html.matches("2026-10-31 22:13:09").count() >= 2);
        assert!(html.contains("已就绪"));
        assert!(html.contains("正常"));
        assert!(!html.contains("生成中"));
        for (name, value) in [
            ("匿名读取", "60 次/分钟/IP"),
            ("带密钥读取", "600 次/分钟/密钥"),
            ("上传、修改、删除", "60 次/分钟/密钥"),
            ("申请密钥", "5 次/小时/IP"),
            ("邮件链接确认", "20 次/小时/IP"),
            ("举报", "10 次/小时/IP"),
            ("认证失败", "30 次/分钟/IP"),
            ("每个账号每小时新建模板", "100 条/小时"),
            ("每个账号的模板总数上限", "1000 条"),
        ] {
            assert!(html.contains(name), "{name}");
            assert!(html.contains(value), "{value}");
        }
        assert!(crate::html::tests::attribute_problems(&html).is_empty());
        assert!(html.contains("@media (prefers-color-scheme: dark)"));
        assert!(html.contains("min(100%, 720px)"));
        assert!(!html.contains("<script"), "不允许脚本");
        assert!(!html.contains("src="), "不允许资源引用");
        assert!(html.len() <= 20 * 1024, "{} 字节", html.len());
        assert!(html.contains("class=\"note\">AGPL-3.0 开源<"));
        for (href, label) in [
            ("/", "返回首页"),
            ("/llms.txt", "接口说明"),
            ("/v1/status", "JSON 版本"),
        ] {
            assert!(
                html.contains(&format!("href=\"{href}\">{label}</a>")),
                "{label}"
            );
        }
        assert!(html.contains("grid-template-columns: repeat(3, 1fr)"));
        assert!(html.contains("margin-top: 16px"));
    }

    #[test]
    fn status_page_without_snapshot_hides_hash() {
        const HASH: &str = "7be5040b6c82f1349f8a71f2aae9db776dd828da60d2cbc4f595d0bf8161ebe4";
        let html = status_page(&fixed_status(false));
        assert!(html.contains("生成中"));
        assert!(html.contains("<p class=\"muted\">快照还在生成中，稍后刷新本页</p>"));
        assert!(!html.contains(HASH));
        assert!(!html.contains("<dl"));
        assert!(!html.contains("已就绪"));
        assert!(html.contains("class=\"dot wait\""));
    }

    #[test]
    fn status_page_escapes_dynamic_values() {
        let mut status = fixed_status(true);
        status.version = r#"v<1>"quoted""#.to_string();
        status.catalog.as_mut().unwrap().hash = r#"ab<c>"d"#.to_string();
        let html = status_page(&status);
        assert!(html.contains("v&lt;1&gt;&quot;quoted&quot;"));
        assert!(!html.contains(r#"v<1>"#));
        assert!(html.contains("ab&lt;c&gt;&quot;d"));
        assert!(!html.contains(r#"ab<c>"#));
    }

    #[test]
    fn status_page_missing_rate_limit_is_dash() {
        let mut status = fixed_status(true);
        status
            .rate_limits
            .as_object_mut()
            .unwrap()
            .remove("report_per_hour_per_ip");
        let html = status_page(&status);
        assert!(html.contains("<td>举报</td><td>—</td>"));
    }
}
