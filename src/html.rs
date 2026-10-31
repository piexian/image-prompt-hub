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
pub mod tests {
    use super::*;

    /// 属性良构检查：对每个开标签解析属性，要求值用引号包裹且闭合引号之后
    /// （标签内）只能是空白或自闭合斜杠。字体栈含单引号，若属性误用单引号包裹，
    /// 值会在内部引号处被截断，这个扫描器会抓到。
    pub fn attribute_problems(html: &str) -> Vec<String> {
        let chars: Vec<char> = html.chars().collect();
        let mut problems = Vec::new();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '<' && chars.get(i + 1).is_some_and(|c| c.is_ascii_alphabetic()) {
                let mut j = i + 1;
                while j < chars.len() && chars[j] != '>' {
                    j += 1;
                }
                if j >= chars.len() {
                    problems.push(format!(
                        "标签未闭合：{}",
                        chars[i..].iter().collect::<String>()
                    ));
                    break;
                }
                let tag: String = chars[i..=j].iter().collect();
                let mut k = i + 1;
                while k < j && chars[k].is_ascii_alphanumeric() {
                    k += 1;
                }
                while k < j {
                    while k < j && chars[k].is_whitespace() {
                        k += 1;
                    }
                    if k >= j {
                        break;
                    }
                    if chars[k] == '/' {
                        k += 1;
                        continue;
                    }
                    let name_start = k;
                    while k < j && chars[k] != '=' && !chars[k].is_whitespace() {
                        k += 1;
                    }
                    let name: String = chars[name_start..k].iter().collect();
                    if k < j && chars[k] == '=' {
                        k += 1;
                        let quote = chars[k];
                        if quote != '"' && quote != '\'' {
                            problems.push(format!("属性 {name} 未用引号包裹：{tag}"));
                            break;
                        }
                        k += 1;
                        while k < j && chars[k] != quote {
                            k += 1;
                        }
                        if k >= j {
                            problems.push(format!("属性 {name} 的值未闭合：{tag}"));
                            break;
                        }
                        k += 1;
                        if k < j {
                            let next = chars[k];
                            if !next.is_whitespace() && next != '/' {
                                problems.push(format!(
                                    "属性 {name} 的值在内部引号处被截断（后面是 {next:?}）：{tag}"
                                ));
                                break;
                            }
                        }
                    }
                }
                i = j + 1;
            } else {
                i += 1;
            }
        }
        problems
    }

    #[test]
    fn escapes_all_specials() {
        assert_eq!(escape_html("a<b>&\"'c"), "a&lt;b&gt;&amp;&quot;&#x27;c");
        assert_eq!(escape_html("普通中文"), "普通中文");
    }
}
