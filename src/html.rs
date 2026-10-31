//! HTML 转义：页面与邮件模板共用的唯一实现。

/// 转义 HTML 特殊字符（含属性上下文用的引号），动态值插进 HTML 前必须经过这里。
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_all_specials() {
        assert_eq!(escape_html("a<b>&\"'c"), "a&lt;b&gt;&amp;&quot;&#x27;c");
        assert_eq!(escape_html("普通中文"), "普通中文");
    }
}
