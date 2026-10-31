//! 邮件模板：验证邮件与密钥邮件，各含纯文本与 HTML 两个版本。
//! HTML 采用表格布局、全部内联样式，无图片、脚本与外部资源，
//! 纯文本保留全部关键信息（链接、密钥、说明）。

use crate::html::escape_html;

/// 一封邮件的两部分内容。`text` 是不支持 HTML 的客户端看到的回退内容。
pub struct EmailContent {
    pub text: String,
    pub html: String,
}

const FONT_STACK: &str =
    "-apple-system,'PingFang SC','Microsoft YaHei','Segoe UI',Arial,sans-serif";
const MONO_STACK: &str = "'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace";
/// 三个装饰色块：粉、柠檬黄、薄荷。
const DOTS_HTML: &str = "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin:12px 0 0;\"><tr><td width=\"10\" height=\"10\" bgcolor=\"#FD79A8\" style=\"border-radius:999px;font-size:0;line-height:0;\">&nbsp;</td><td width=\"6\" style=\"font-size:0;line-height:0;\">&nbsp;</td><td width=\"10\" height=\"10\" bgcolor=\"#FFC93C\" style=\"border-radius:999px;font-size:0;line-height:0;\">&nbsp;</td><td width=\"6\" style=\"font-size:0;line-height:0;\">&nbsp;</td><td width=\"10\" height=\"10\" bgcolor=\"#00B894\" style=\"border-radius:999px;font-size:0;line-height:0;\">&nbsp;</td></tr></table>";

/// 邮件 HTML 骨架：隐藏预览文本、居中 600px 表格、顶部渐变色带与页脚。
fn shell(preheader: &str, heading: &str, body_html: &str) -> String {
    format!(
        r##"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light only">
<style>
:root {{ color-scheme: light only; }}
@media (max-width:620px) {{
  .card {{ padding:20px 16px !important; }}
  .title {{ font-size:20px !important; }}
}}
</style>
</head>
<body style="margin:0;padding:0;background-color:#F4F1FF;">
<div style="display:none;max-height:0;overflow:hidden;mso-hide:all;">{preheader}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#F4F1FF;">
<tr><td align="center" style="padding:24px 12px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;">
<tr><td bgcolor="#6C5CE7" style="background-color:#6C5CE7;background-image:linear-gradient(135deg,#6C5CE7,#FD79A8);border-radius:16px 16px 0 0;padding:24px 28px 18px;">
  <span style="font-family:{FONT_STACK};color:#ffffff;font-weight:700;font-size:18px;">image-prompt-hub</span><br>
  <span style="font-family:{FONT_STACK};color:#ffffff;font-size:12px;">AstrBot 图片生成插件 · 在线提示词模板库</span>
  {DOTS_HTML}
</td></tr>
<tr><td bgcolor="#ffffff" class="card" style="background-color:#ffffff;padding:28px;font-family:{FONT_STACK};color:#2D2A4A;">
<h1 class="title" style="margin:0 0 14px;font-size:22px;font-weight:700;color:#2D2A4A;">{heading}</h1>
{body_html}
</td></tr>
<tr><td style="padding:14px 8px;text-align:center;font-family:{FONT_STACK};font-size:12px;color:#6B6885;">此邮件由系统自动发送，请勿直接回复 · image-prompt-hub 开源提示词模板服务</td></tr>
</table>
</td></tr>
</table>
</body>
</html>"##
    )
}

/// 提示块（浅黄底 + 黄色左边框）。
fn tip_block(text: &str) -> String {
    format!(
        "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin:16px 0 0;\"><tr><td bgcolor=\"#FFF4D6\" style=\"background-color:#FFF4D6;border-left:4px solid #FFC93C;border-radius:8px;padding:12px 16px;\"><p style=\"margin:0;font-size:13px;line-height:1.6;color:#6B5518;\">{}</p></td></tr></table>",
        escape_html(text)
    )
}

/// 防弹按钮：带 bgcolor 的圆角 td 包裹内边距链接，下面附纯文本后备链接。
fn action_button(label: &str, link: &str) -> String {
    let escaped = escape_html(link);
    format!(
        "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" align=\"center\" style=\"margin:22px auto 6px;\"><tr><td bgcolor=\"#F76707\" style=\"background-color:#F76707;border-radius:999px;\"><a href=\"{escaped}\" style=\"display:inline-block;padding:14px 40px;font-family:{FONT_STACK};font-size:18px;font-weight:700;color:#ffffff;text-decoration:none;border-radius:999px;\">{label}</a></td></tr></table><p style=\"margin:8px 0 0;text-align:center;font-size:12px;color:#6B6885;word-break:break-all;\">按钮点不了时，打开这个链接：<br><a href=\"{escaped}\" style=\"font-family:{MONO_STACK};font-size:12px;color:#6B6885;word-break:break-all;text-decoration:underline;\">{escaped}</a></p>",
        label = escape_html(label),
    )
}

/// 彩色数字圆点 + 一句步骤说明。
fn step(number: u8, color: &str, text: &str) -> String {
    format!(
        "<p style=\"margin:10px 0;font-size:14px;line-height:1.6;color:#2D2A4A;\"><span style=\"display:inline-block;width:22px;height:22px;line-height:22px;margin-right:8px;border-radius:999px;background-color:{color};color:#ffffff;font-size:12px;font-weight:700;text-align:center;\">{number}</span>{}</p>",
        escape_html(text)
    )
}

/// 验证邮件。purpose 为 `issue` 或 `reset`，措辞沿用原纯文本语义。
pub fn verification_email(purpose: &str, link: &str) -> EmailContent {
    let (action, heading, preheader, button) = if purpose == "reset" {
        (
            "重置 API 密钥。确认后将生成新密钥，并立即作废你当前有效的密钥。",
            "重置你的 API 密钥",
            "30 分钟内打开链接并点击“确认”，即可完成 API 密钥重置",
            "确认重置",
        )
    } else {
        (
            "申请 API 密钥。确认后新密钥将发送到这个邮箱。",
            "确认你的邮箱",
            "30 分钟内打开链接并点击“确认”，即可完成 API 密钥申请",
            "确认邮箱",
        )
    };
    let text = format!(
        "你（或他人）正在为这个邮箱{action}。\n\n\
         请在 30 分钟内打开下面的链接并点击“确认”按钮完成操作：\n\
         {link}\n\n\
         打开链接本身不会生效，必须在页面上点击“确认”。\n\
         如果不是你本人的操作，忽略这封邮件即可，不会有任何影响。\n"
    );
    let tip = tip_block("30 分钟内有效；打开链接本身不会生效，要在页面上点击“确认”");
    let body = format!(
        "<p style=\"margin:0 0 6px;font-size:15px;line-height:1.7;color:#2D2A4A;\">{}</p>\
         {}\
         {}\
         <p style=\"margin:18px 0 0;font-size:13px;line-height:1.6;color:#6B6885;\">不是你本人的操作？忽略这封邮件即可，不会有任何影响。</p>",
        escape_html(action),
        action_button(button, link),
        tip,
    );
    EmailContent {
        text,
        html: shell(preheader, heading, &body),
    }
}

/// 密钥邮件：密钥本体、三步使用说明与吊销链接。
pub fn api_key_email(key: &str, revoke_link: &str) -> EmailContent {
    let text = format!(
        "你的 API 密钥如下，只显示这一次，请妥善保存：\n\n\
         {key}\n\n\
         在 AstrBot 图片生成插件的提示词广场“在线”页里选择“填写密钥”并粘贴上面的密钥即可使用。\n\n\
         吊销方式：打开下面的链接，在页面上点击“确认吊销”即可（打开链接本身不会吊销）：\n\
         {revoke_link}\n\
         也可以用同一邮箱重新申请，重置会作废旧密钥。\n"
    );
    let key_box = format!(
        "<div style=\"margin:4px 0 8px;background-color:#F4F1FF;border:2px dashed #6C5CE7;border-radius:12px;padding:16px;text-align:center;\"><code style=\"font-family:{MONO_STACK};font-size:16px;color:#2D2A4A;word-break:break-all;\">{}</code></div>",
        escape_html(key)
    );
    let steps = format!(
        "{}{}{}",
        step(1, "#6C5CE7", "打开 AstrBot 插件 WebUI"),
        step(2, "#FD79A8", "进入“提示词广场”→“在线”"),
        step(3, "#00B894", "选择“填写密钥”并粘贴"),
    );
    let revoke = format!(
        "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin:20px 0 0;\"><tr><td style=\"border:2px solid #6C5CE7;border-radius:12px;padding:16px;text-align:center;\"><p style=\"margin:0 0 12px;font-size:14px;font-weight:700;color:#2D2A4A;\">密钥泄露了或不再使用？</p><table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" align=\"center\"><tr><td style=\"border:2px solid #6C5CE7;border-radius:999px;background-color:#ffffff;\"><a href=\"{}\" style=\"display:inline-block;padding:10px 30px;font-family:{FONT_STACK};font-size:14px;font-weight:600;color:#6C5CE7;text-decoration:none;border-radius:999px;\">吊销这把密钥</a></td></tr></table><p style=\"margin:12px 0 0;font-size:12px;line-height:1.6;color:#6B6885;word-break:break-all;\">点击后先打开确认页，不会立刻吊销；吊销后可用同一邮箱重新申请：<br><a href=\"{}\" style=\"font-family:{MONO_STACK};font-size:12px;color:#6B6885;word-break:break-all;text-decoration:underline;\">{}</a></p></td></tr></table>",
        escape_html(revoke_link),
        escape_html(revoke_link),
        escape_html(revoke_link),
    );
    let body = format!(
        "<p style=\"margin:0 0 12px;font-size:15px;line-height:1.7;color:#2D2A4A;\">你的 API 密钥如下：</p>\
         {key_box}\
         {}\
         <p style=\"margin:16px 0 8px;font-size:14px;font-weight:700;color:#2D2A4A;\">使用方法</p>\
         {steps}\
         {revoke}",
        tip_block("只显示这一次，请妥善保存"),
    );
    EmailContent {
        text,
        html: shell(
            "你的 API 密钥已就绪，请妥善保存",
            "你的 API 密钥已就绪",
            &body,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::html::tests::attribute_problems;

    const LINK: &str = "https://hub.example.com/v1/keys/verify?token=abc123";

    #[test]
    fn attribute_scanner_catches_broken_style() {
        // 单引号属性 + 含单引号的字体栈：属性在内部引号处被截断，必须被抓到
        let broken = "<a href=\"https://x\" style='font-family:-apple-system,'PingFang SC',sans-serif;color:#fff;'>按钮</a>";
        assert!(
            attribute_problems(broken)
                .iter()
                .any(|p| p.contains("被截断")),
            "扫描器应抓到截断的 style：{:?}",
            attribute_problems(broken)
        );
        // 正确写法：无问题
        let ok = "<a href=\"https://x\" style=\"font-family:-apple-system,'PingFang SC',sans-serif;color:#fff;\">按钮</a>";
        assert!(
            attribute_problems(ok).is_empty(),
            "{:?}",
            attribute_problems(ok)
        );
        // 自闭合与无值属性
        assert!(attribute_problems("<br><input disabled><img alt=\"x\" />").is_empty());
    }

    #[test]
    fn all_email_attributes_well_formed() {
        let revoke = "https://hub.example.com/v1/keys/revoke?token=r";
        for html in [
            verification_email("issue", LINK).html,
            verification_email("reset", LINK).html,
            api_key_email("iph_k", revoke).html,
        ] {
            let problems = attribute_problems(&html);
            assert!(problems.is_empty(), "属性良构检查失败：{problems:#?}");
        }
    }

    #[test]
    fn button_styles_survive_in_all_emails() {
        // 主按钮（验证邮件两封）：白色文字、无下划线，且与珊瑚橙背景同处一个 a 标签
        for purpose in ["issue", "reset"] {
            let html = verification_email(purpose, LINK).html;
            assert!(
                html.contains("background-color:#F76707")
                    && html.contains("color:#ffffff;text-decoration:none"),
                "主按钮样式不完整：应同时含橙色背景与白色无下划线文字"
            );
        }
        // 密钥邮件：吊销按钮描边紫色无下划线、密钥框等宽可断行
        let key_html =
            api_key_email("iph_k", "https://hub.example.com/v1/keys/revoke?token=r").html;
        assert!(
            key_html.contains("color:#6C5CE7;text-decoration:none"),
            "吊销按钮样式不完整"
        );
        assert!(
            key_html.matches("word-break:break-all").count() >= 3,
            "后备链接与密钥框都应可断行"
        );
    }

    #[test]
    fn verification_text_keeps_existing_wording() {
        for purpose in ["issue", "reset"] {
            let mail = verification_email(purpose, LINK);
            assert!(mail.text.contains(LINK), "纯文本必须包含链接");
            assert!(mail.text.contains("30 分钟内"));
            assert!(mail.text.contains("忽略这封邮件即可，不会有任何影响"));
        }
        assert!(verification_email("issue", LINK)
            .text
            .contains("申请 API 密钥"));
        assert!(verification_email("reset", LINK)
            .text
            .contains("重置 API 密钥。确认后将生成新密钥，并立即作废你当前有效的密钥。"));
    }

    #[test]
    fn api_key_text_keeps_existing_wording() {
        let mail = api_key_email(
            "iph_test123",
            "https://hub.example.com/v1/keys/revoke?token=r",
        );
        assert!(mail.text.contains("iph_test123"));
        assert!(mail
            .text
            .contains("https://hub.example.com/v1/keys/revoke?token=r"));
        assert!(mail.text.contains("确认吊销"));
        assert!(!mail.text.contains("DELETE /v1/key"));
        // 密钥同时出现在 HTML 里
        assert!(mail.html.contains("iph_test123"));
    }

    #[test]
    fn html_shape_and_safety() {
        for html in [
            verification_email("issue", LINK).html,
            verification_email("reset", LINK).html,
            api_key_email("iph_k", "https://hub.example.com/v1/keys/revoke?token=r").html,
        ] {
            assert!(html.contains("lang=\"zh-CN\""));
            assert!(html.contains("viewport"));
            assert!(!html.contains("<script"), "不允许脚本");
            assert!(!html.contains("src="), "不允许任何资源引用");
            assert!(!html.contains("@import"), "不允许外部样式");
            assert!(!html.contains("url("), "不允许 url() 引用");
            assert!(
                html.len() <= 30 * 1024,
                "HTML 应在 30KB 内：{} 字节",
                html.len()
            );
            // 除传入链接外不允许其他 http://
            let stripped = html
                .replace(LINK, "")
                .replace("https://hub.example.com/v1/keys/revoke?token=r", "");
            assert!(!stripped.contains("http://"), "不得出现外部链接");
        }
    }

    #[test]
    fn html_uses_exact_escaped_href() {
        let html = verification_email("issue", LINK).html;
        let href = format!("href=\"{}\"", escape_html(LINK));
        assert!(html.contains(&href), "按钮与后备链接都应指向链接本身");
        assert!(html.matches(&href).count() >= 2);
    }

    #[test]
    fn dynamic_values_are_escaped() {
        let nasty = "https://h.e/v?a=1&b=<z>\"q'&x=y";
        let mail = verification_email("issue", nasty);
        let escaped = escape_html(nasty);
        assert!(mail.html.contains(&format!("href=\"{escaped}\"")));
        assert!(
            !mail.html.contains("href='https://h.e/v?a=1&b=<z>'"),
            "原始值不得直接进属性"
        );
        let key_mail = api_key_email("iph_<k>&\"'", "https://h.e/r");
        assert!(key_mail.html.contains("iph_&lt;k&gt;&amp;&quot;&#x27;"));
    }

    #[test]
    fn html_wording_by_purpose() {
        let issue = verification_email("issue", LINK).html;
        let reset = verification_email("reset", LINK).html;
        assert!(issue.contains("确认你的邮箱"));
        assert!(reset.contains("重置你的 API 密钥"));
        assert!(issue.contains("确认邮箱</a>"), "申请的主按钮文案");
        assert!(reset.contains("确认重置</a>"), "重置的主按钮文案");
        assert!(
            !reset.contains("确认邮箱</a>"),
            "重置不应沿用申请的按钮文案"
        );
        assert!(reset.contains("立即作废你当前有效的密钥"));
        // 黄色提示块与安全页脚
        for html in [&issue, &reset] {
            assert!(html.contains("打开链接本身不会生效，要在页面上点击“确认”"));
            assert!(html.contains("不是你本人的操作？忽略这封邮件即可，不会有任何影响"));
            assert!(html.contains("此邮件由系统自动发送，请勿直接回复"));
            assert!(html.contains("image-prompt-hub"));
            assert!(html.contains("AstrBot 图片生成插件 · 在线提示词模板库"));
        }
    }

    #[test]
    fn api_key_html_structure() {
        let html = api_key_email("iph_k", "https://hub.example.com/v1/keys/revoke?token=r").html;
        assert!(html.contains("你的 API 密钥已就绪"));
        assert!(html.contains("只显示这一次，请妥善保存"));
        assert!(html.contains("打开 AstrBot 插件 WebUI"));
        assert!(html.contains("提示词广场"));
        assert!(html.contains("吊销这把密钥"));
        assert!(html.contains("点击后先打开确认页，不会立刻吊销"));
        assert!(html.contains("word-break:break-all"));
    }

    #[test]
    fn preheader_present() {
        let issue = verification_email("issue", LINK).html;
        assert!(issue.contains("30 分钟内打开链接并点击“确认”，即可完成 API 密钥申请"));
        let key = api_key_email("iph_k", "https://h.e/r").html;
        assert!(key.contains("你的 API 密钥已就绪，请妥善保存"));
    }
}
