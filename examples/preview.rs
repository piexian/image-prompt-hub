//! 开发用预览：把三种邮件的 HTML 与纯文本写到 target/preview/emails/，
//! 在浏览器里直接打开 .html 查看效果。不进正式二进制。

use image_prompt_hub::email::templates::{api_key_email, verification_email, EmailContent};

const BASE: &str = "https://hub.example.com";

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
}
