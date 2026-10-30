//! 模板字段校验与邮箱规范化。字数一律按 Unicode 字符计。

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::config::DomainRule;

pub const ALLOWED_PLACEHOLDERS: [&str; 3] = ["{{input}}", "{{rows}}", "{{cols}}"];
const NAME_MAX: usize = 40;
const DESCRIPTION_MAX: usize = 80;
const CONTENT_MAX: usize = 8000;
const AUTHOR_MAX: usize = 32;
const TAG_COUNT_MAX: usize = 10;
const TAG_LEN_MAX: usize = 20;

/// 去掉换行与控制字符，保持单行文本。
pub fn strip_control_chars(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// 是否含有除换行、回车、制表符以外的控制字符。
/// NUL 会让 PostgreSQL 直接报错，其余控制字符对多行文本没有合法用途。
pub fn has_forbidden_control(s: &str) -> bool {
    s.chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}

fn char_len(s: &str) -> usize {
    s.chars().count()
}

/// `^[0-9]{1,2}K$`
pub fn is_valid_resolution(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes.len() > 3 {
        return false;
    }
    if bytes[bytes.len() - 1] != b'K' {
        return false;
    }
    bytes[..bytes.len() - 1].iter().all(|b| b.is_ascii_digit())
}

/// `^[0-9]{1,2}:[0-9]{1,2}$`
pub fn is_valid_aspect_ratio(value: &str) -> bool {
    let Some((left, right)) = value.split_once(':') else {
        return false;
    };
    (1..=2).contains(&left.len())
        && (1..=2).contains(&right.len())
        && left.bytes().all(|b| b.is_ascii_digit())
        && right.bytes().all(|b| b.is_ascii_digit())
}

/// 正文里只允许 `{{input}}`、`{{rows}}`、`{{cols}}` 三种占位符。
pub fn check_placeholders(content: &str) -> Result<(), String> {
    let mut rest = content;
    while let Some(start) = rest.find("{{") {
        let after_start = &rest[start..];
        if let Some(end) = after_start.find("}}") {
            let placeholder = &after_start[..end + 2];
            if !ALLOWED_PLACEHOLDERS.contains(&placeholder) {
                return Err(format!("正文包含不支持的占位符：{placeholder}，只允许 {{{{input}}}}、{{{{rows}}}}、{{{{cols}}}}"));
            }
            rest = &after_start[end + 2..];
        } else {
            return Err("正文包含未闭合的 {{ 占位符".to_string());
        }
    }
    Ok(())
}

/// 上传 / 修改请求体。`nsfw` 字段单独拦截。
#[derive(Debug, Clone, Deserialize)]
pub struct TemplateUpsert {
    pub name: Option<String>,
    pub ai_description: Option<String>,
    pub content: Option<String>,
    pub defaults: Option<Value>,
    pub reference: Option<String>,
    pub tags: Option<Vec<String>>,
    pub author: Option<String>,
    #[allow(dead_code)]
    pub nsfw: Option<bool>,
}

pub fn validate_upsert(input: &TemplateUpsert) -> Result<ValidatedTemplate, String> {
    if input.nsfw == Some(true) {
        return Err("不接受 nsfw 内容".to_string());
    }

    let Some(raw_name) = &input.name else {
        return Err("缺少 name 字段".to_string());
    };
    let name = raw_name.trim().to_string();
    if name.is_empty() || char_len(&name) > NAME_MAX {
        return Err(format!("name 必须是 1 到 {NAME_MAX} 字"));
    }
    let name = strip_control_chars(&name);
    if name.is_empty() || char_len(&name) > NAME_MAX {
        return Err(format!("name 必须是 1 到 {NAME_MAX} 字"));
    }

    let ai_description = match &input.ai_description {
        Some(desc) => {
            let desc = strip_control_chars(desc.trim());
            if char_len(&desc) > DESCRIPTION_MAX {
                return Err(format!("ai_description 不能超过 {DESCRIPTION_MAX} 字"));
            }
            desc
        }
        None => String::new(),
    };

    let Some(content) = &input.content else {
        return Err("缺少 content 字段".to_string());
    };
    let content = content.trim().to_string();
    if content.is_empty() || char_len(&content) > CONTENT_MAX {
        return Err(format!("content 必须是 1 到 {CONTENT_MAX} 字"));
    }
    if has_forbidden_control(&content) {
        return Err("content 不能包含除换行、回车、制表符以外的控制字符".to_string());
    }
    check_placeholders(&content)?;

    let defaults = validate_defaults(input.defaults.as_ref())?;
    let reference = match input.reference.as_deref() {
        None | Some("") => "none".to_string(),
        Some(value) => match value {
            "none" | "optional" | "required" => value.to_string(),
            other => return Err(format!("reference 的取值无效：{other}")),
        },
    };

    let tags = normalize_tags(input.tags.as_deref())?;

    let author = match &input.author {
        Some(author) => {
            let author = strip_control_chars(author.trim());
            if char_len(&author) > AUTHOR_MAX {
                return Err(format!("author 不能超过 {AUTHOR_MAX} 字"));
            }
            if author.is_empty() {
                None
            } else {
                Some(author)
            }
        }
        None => None,
    };

    Ok(ValidatedTemplate {
        name,
        ai_description,
        content,
        defaults,
        reference,
        tags,
        author,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTemplate {
    pub name: String,
    pub ai_description: String,
    pub content: String,
    pub defaults: Value,
    pub reference: String,
    pub tags: Vec<String>,
    pub author: Option<String>,
}

/// defaults 只允许 `resolution` 与 `aspect_ratio` 两个键。
pub fn validate_defaults(value: Option<&Value>) -> Result<Value, String> {
    let Some(value) = value else {
        return Ok(json!({}));
    };
    let Some(object) = value.as_object() else {
        return Err("defaults 必须是对象".to_string());
    };
    let mut out = Map::new();
    for (key, item) in object {
        match key.as_str() {
            "resolution" => {
                let Some(resolution) = item.as_str() else {
                    return Err("defaults.resolution 必须是字符串".to_string());
                };
                if !is_valid_resolution(resolution) {
                    return Err("defaults.resolution 必须形如 2K（一到两位数字加 K）".to_string());
                }
                out.insert("resolution".to_string(), json!(resolution));
            }
            "aspect_ratio" => {
                let Some(ratio) = item.as_str() else {
                    return Err("defaults.aspect_ratio 必须是字符串".to_string());
                };
                if !is_valid_aspect_ratio(ratio) {
                    return Err("defaults.aspect_ratio 必须形如 16:9".to_string());
                }
                out.insert("aspect_ratio".to_string(), json!(ratio));
            }
            other => return Err(format!("defaults 不支持的字段：{other}")),
        }
    }
    Ok(Value::Object(out))
}

/// 标签去重（保持顺序）、限长、去控制字符。
pub fn normalize_tags(tags: Option<&[String]>) -> Result<Vec<String>, String> {
    let Some(tags) = tags else {
        return Ok(Vec::new());
    };
    if tags.len() > TAG_COUNT_MAX {
        return Err(format!("标签不能超过 {TAG_COUNT_MAX} 个"));
    }
    let mut seen = Vec::new();
    for tag in tags {
        let tag = strip_control_chars(tag.trim());
        if tag.is_empty() || char_len(&tag) > TAG_LEN_MAX {
            return Err(format!("每个标签必须是 1 到 {TAG_LEN_MAX} 字"));
        }
        if !seen.contains(&tag) {
            seen.push(tag);
        }
    }
    Ok(seen)
}

/// 收件地址规范化：去空白、转小写。发信使用这个地址。
pub fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn is_valid_local_part(local: &str) -> bool {
    (1..=64).contains(&local.len())
        && local
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'%' | b'+' | b'-'))
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
}

fn is_valid_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.is_ascii()
        && domain.contains('.')
        && domain.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label.starts_with(|c: char| c.is_ascii_alphanumeric())
                && label.ends_with(|c: char| c.is_ascii_alphanumeric())
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// 严格格式检查：本地部分 `[a-z0-9._%+-]{1,64}`（不以点开头/结尾、无连续点），
/// 域名 ASCII 按点分段（每段 1–63、不以连字符开头/结尾），整址 ≤254。
pub fn is_valid_email_format(email: &str) -> bool {
    if email.chars().count() > 254 || email.contains(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    is_valid_local_part(local) && is_valid_domain(domain)
}

/// 账号身份（email_hmac 的输入）：gmail.com 去掉本地部分的点和 `+` 之后的内容，
/// 其他域名只去掉 `+` 之后的内容。与发信地址解耦。
pub fn email_identity(email: &str) -> String {
    let email = normalize_email(email);
    let Some((local, domain)) = email.split_once('@') else {
        return email;
    };
    let base = local.split('+').next().unwrap_or(local);
    let base = if domain == "gmail.com" {
        base.replace('.', "")
    } else {
        base.to_string()
    };
    // 本地部分被剥空（例如 `+tag@qq.com`）时保持原样，避免不同地址合并成同一个身份
    let identity = if base.is_empty() {
        local.to_string()
    } else {
        base
    };
    format!("{identity}@{domain}")
}

pub fn email_domain(email: &str) -> Option<&str> {
    email.split_once('@').map(|(_, domain)| domain)
}

/// 后缀白名单检查。
pub fn is_email_allowed(email: &str, allowlist: &[DomainRule]) -> bool {
    match email_domain(email) {
        Some(domain) => allowlist.iter().any(|rule| rule.matches(domain)),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upsert(name: &str, content: &str) -> TemplateUpsert {
        TemplateUpsert {
            name: Some(name.to_string()),
            ai_description: None,
            content: Some(content.to_string()),
            defaults: None,
            reference: None,
            tags: None,
            author: None,
            nsfw: None,
        }
    }

    #[test]
    fn name_length_boundaries() {
        let ok41 = "x".repeat(41);
        let ok40 = "x".repeat(40);
        assert!(validate_upsert(&upsert(&ok40, "c")).is_ok());
        assert!(validate_upsert(&upsert(&ok41, "c")).is_err());
        assert!(validate_upsert(&upsert("", "c")).is_err());
        assert!(validate_upsert(&upsert("  ", "c")).is_err());
        // 中文按字符计
        let cn40 = "字".repeat(40);
        let cn41 = "字".repeat(41);
        assert!(validate_upsert(&upsert(&cn40, "c")).is_ok());
        assert!(validate_upsert(&upsert(&cn41, "c")).is_err());
    }

    #[test]
    fn control_chars_stripped() {
        let mut input = upsert("名字", "c");
        input.ai_description = Some("说\n明\r内\u{0000}容".to_string());
        input.author = Some("作\u{0001}者\t名".to_string());
        let validated = validate_upsert(&input).unwrap();
        assert_eq!(validated.ai_description, "说明内容");
        assert_eq!(validated.author.as_deref(), Some("作者名"));
    }

    #[test]
    fn content_boundaries() {
        let max = "a".repeat(8000);
        let over = "a".repeat(8001);
        assert!(validate_upsert(&upsert("n", &max)).is_ok());
        assert!(validate_upsert(&upsert("n", &over)).is_err());
        assert!(validate_upsert(&upsert("n", "")).is_err());
        assert!(validate_upsert(&upsert("n", "   ")).is_err());
    }

    #[test]
    fn placeholder_rules() {
        assert!(check_placeholders("画一只猫 {{input}}").is_ok());
        assert!(check_placeholders("{{rows}}x{{cols}}").is_ok());
        assert!(check_placeholders("{{ input }}").is_err());
        assert!(check_placeholders("{{user_input}}").is_err());
        assert!(check_placeholders("{{}}").is_err());
        assert!(check_placeholders("{{未闭合").is_err());
        assert!(validate_upsert(&upsert("n", "{{other}} 画面")).is_err());
    }

    #[test]
    fn resolution_and_ratio() {
        assert!(is_valid_resolution("2K"));
        assert!(is_valid_resolution("12K"));
        assert!(!is_valid_resolution("123K"));
        assert!(!is_valid_resolution("K"));
        assert!(!is_valid_resolution("2k"));
        assert!(!is_valid_resolution("2 M"));
        assert!(is_valid_aspect_ratio("16:9"));
        assert!(is_valid_aspect_ratio("1:1"));
        assert!(!is_valid_aspect_ratio("16:"));
        assert!(!is_valid_aspect_ratio(":9"));
        assert!(!is_valid_aspect_ratio("123:9"));
        assert!(!is_valid_aspect_ratio("16:9:2"));
    }

    #[test]
    fn defaults_validation() {
        assert!(validate_defaults(None).is_ok());
        assert!(validate_defaults(Some(&json!({"resolution": "2K"}))).is_ok());
        assert!(validate_defaults(Some(&json!({"aspect_ratio": "4:3"}))).is_ok());
        assert!(validate_defaults(Some(&json!({"other": 1}))).is_err());
        assert!(validate_defaults(Some(&json!("str"))).is_err());
        assert!(validate_defaults(Some(&json!({"resolution": "2k"}))).is_err());
        assert!(validate_defaults(Some(&json!({"aspect_ratio": "16x9"}))).is_err());
    }

    #[test]
    fn reference_values() {
        let mut input = upsert("n", "c");
        for ok in ["none", "optional", "required"] {
            input.reference = Some(ok.to_string());
            assert_eq!(validate_upsert(&input).unwrap().reference, ok);
        }
        input.reference = Some("sometimes".to_string());
        assert!(validate_upsert(&input).is_err());
    }

    #[test]
    fn tag_rules() {
        assert_eq!(
            normalize_tags(Some(&["a".into(), "a".into(), " b ".into()])).unwrap(),
            vec!["a", "b"]
        );
        let eleven: Vec<String> = (0..11).map(|i| i.to_string()).collect();
        assert!(normalize_tags(Some(&eleven)).is_err());
        let long = "x".repeat(21);
        assert!(normalize_tags(Some(&[long])).is_err());
        let twenty = "字".repeat(20);
        assert!(normalize_tags(Some(std::slice::from_ref(&twenty))).is_ok());
        assert!(normalize_tags(Some(&["".into()])).is_err());
    }

    #[test]
    fn nsfw_rejected() {
        let mut input = upsert("n", "c");
        input.nsfw = Some(true);
        assert!(validate_upsert(&input).is_err());
        input.nsfw = Some(false);
        assert!(validate_upsert(&input).is_ok());
    }

    #[test]
    fn email_normalization() {
        assert_eq!(
            normalize_email("  User@Example.QQ.COM \n"),
            "user@example.qq.com"
        );
        assert!(is_valid_email_format("user@qq.com"));
        assert!(!is_valid_email_format("userqq.com"));
        assert!(!is_valid_email_format("@qq.com"));
        assert!(!is_valid_email_format("user@"));
        assert!(!is_valid_email_format("user@@qq.com"));
        assert!(!is_valid_email_format("user@.com"));
        assert!(!is_valid_email_format("user@qq."));
        assert!(!is_valid_email_format("us er@qq.com"));
    }

    #[test]
    fn email_format_accepts_documented_shapes() {
        for ok in [
            "a@qq.com",
            "first.last@qq.com",
            "a_b%c+d-e@sub.pku.edu.cn",
            "1234567@qq.com",
            "x@a-b.c-d.edu.cn",
        ] {
            assert!(is_valid_email_format(ok), "{ok} 应合法");
        }
        // 边界长度：本地部分 64、域名段 63、整址 254
        let local64 = "a".repeat(64);
        assert!(is_valid_email_format(&format!("{local64}@qq.com")));
        let label63 = "b".repeat(63);
        assert!(is_valid_email_format(&format!("x@{label63}.edu.cn")));
        let label60 = "c".repeat(60);
        let exactly_254 = format!("{local64}@{label60}.{label60}.{label60}.cccccc");
        assert_eq!(exactly_254.chars().count(), 254);
        assert!(is_valid_email_format(&exactly_254));
        assert!(
            !is_valid_email_format(&format!("{exactly_254}c")),
            "255 字符应被拒绝"
        );
    }

    #[test]
    fn email_format_rejects_malformed_addresses() {
        let local65 = "a".repeat(65);
        let label64 = "b".repeat(64);
        let label60 = "c".repeat(60);
        // 域名 247 字符本身合法（≤253），但加上 64 字符本地部分后整址超过 254
        let over_254 = format!(
            "{}@{label60}.{label60}.{label60}.{label60}.com",
            "a".repeat(64)
        );
        // 域名超过 253
        let too_long_domain = format!("x@{label60}.{label60}.{label60}.{label60}.{label60}.com");
        for (bad, why) in [
            ("a..b@qq.com", "本地部分连续的点"),
            (".a@qq.com", "本地部分以点开头"),
            ("a.@qq.com", "本地部分以点结尾"),
            ("a@x..edu.cn", "域名连续的点"),
            ("a@.qq.com", "域名以点开头"),
            ("a@qq.com.", "域名以点结尾"),
            ("a@-x.edu.cn", "域名段以连字符开头"),
            ("a@x-.edu.cn", "域名段以连字符结尾"),
            ("a@例え.cn", "含非 ASCII 的域名"),
            ("a@qq.cöm", "含非 ASCII 的域名后缀"),
            ("用户@qq.com", "含非 ASCII 的本地部分"),
            ("a@qq_com.cn", "域名含下划线"),
            ("a b@qq.com", "本地部分含空白"),
            ("a@qq.com\n", "尾随换行"),
            ("a@localhost", "域名没有点"),
            ("@qq.com", "本地部分为空"),
            ("a@@qq.com", "多个 @"),
            ("A@qq.com", "未规范化的大写（调用方应先规范化）"),
            ("a,b@qq.com", "本地部分含逗号"),
            ("a(b)@qq.com", "本地部分含括号"),
            ("a\"b@qq.com", "本地部分含引号"),
        ] {
            assert!(!is_valid_email_format(bad), "{bad}（{why}）应被拒绝");
        }
        assert!(
            !is_valid_email_format(&format!("{local65}@qq.com")),
            "本地部分 65"
        );
        assert!(
            !is_valid_email_format(&format!("x@{label64}.edu.cn")),
            "域名段 64"
        );
        assert!(!is_valid_email_format(&over_254), "整址超过 254");
        assert!(!is_valid_email_format(&too_long_domain), "域名超过 253");
    }

    #[test]
    fn email_identity_merges_aliases() {
        // gmail：去掉点和 + 之后的内容
        let gmail = email_identity("ab@gmail.com");
        assert_eq!(email_identity("a.b+x@gmail.com"), gmail);
        assert_eq!(email_identity("A.B@Gmail.COM"), gmail);
        assert_eq!(email_identity(" a.b.+promo+more@gmail.com "), gmail);
        // 其他域名：只去掉 + 之后的内容，点有意义
        assert_eq!(email_identity("x+1@qq.com"), email_identity("x@qq.com"));
        assert_eq!(email_identity("x+1+2@qq.com"), "x@qq.com");
        assert_ne!(email_identity("a.b@qq.com"), email_identity("ab@qq.com"));
        // 不同域名、不同本地部分都是不同身份
        assert_ne!(email_identity("x@qq.com"), email_identity("x@163.com"));
        assert_ne!(email_identity("x@qq.com"), email_identity("y@qq.com"));
        // 本地部分被剥空时保持原样，不同地址不会并成一个身份
        assert_ne!(email_identity("+a@qq.com"), email_identity("+b@qq.com"));
        // 发信地址不受身份规范化影响：只转小写、去空白
        assert_eq!(normalize_email(" A.B+x@Gmail.com "), "a.b+x@gmail.com");
    }

    #[test]
    fn content_forbids_control_characters_except_whitespace() {
        assert!(!has_forbidden_control("多行\n文本\r\n带\t制表"));
        for bad in [
            "a\u{0}b", "a\u{1}b", "a\u{8}b", "a\u{b}b", "a\u{1b}b", "a\u{7f}b", "a\u{85}b",
        ] {
            assert!(has_forbidden_control(bad), "{bad:?} 应判为含控制字符");
            let result = validate_upsert(&upsert("n", &format!("内容{bad}{{{{input}}}}")));
            assert!(
                result.as_ref().is_err_and(|e| e.contains("控制字符")),
                "{bad:?} 应被拒绝：{result:?}"
            );
        }
        // 换行、回车、制表符照常通过，首尾空白仍被裁掉
        let ok = validate_upsert(&upsert("n", "第一行\n第二行\r\n\t缩进 {{input}}\n")).unwrap();
        assert_eq!(ok.content, "第一行\n第二行\r\n\t缩进 {{input}}");
    }

    #[test]
    fn email_allowlist() {
        let rules: Vec<DomainRule> = "qq.com,foxmail.com,163.com,gmail.com,*.edu.cn"
            .split(',')
            .filter_map(DomainRule::parse)
            .collect();
        assert!(is_email_allowed("a@qq.com", &rules));
        assert!(is_email_allowed("a@foxmail.com", &rules));
        assert!(is_email_allowed("a@pku.edu.cn", &rules));
        assert!(is_email_allowed("a@edu.cn", &rules));
        assert!(!is_email_allowed("a@fakeedu.cn", &rules));
        assert!(!is_email_allowed("a@qq.com.evil.io", &rules));
        assert!(!is_email_allowed("a@sub.qq.com", &rules));
        assert!(!is_email_allowed("a@outlook.com", &rules));
        // 大小写在规范化后判断
        let normalized = normalize_email("A@QQ.com");
        assert!(is_email_allowed(&normalized, &rules));
    }
}
