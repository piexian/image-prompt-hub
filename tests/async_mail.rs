//! 申请接口的发信在后台执行：封禁与正常邮箱的响应耗时都与 SMTP 速度无关。

mod common;

/// 结构性耗时验证：假发信器延迟 500ms，两种邮箱都应在远小于延迟的时间内返回，
/// 返回时邮件尚未记录；后台任务结束后正常邮箱恰好 1 封、封禁邮箱 0 封。
#[tokio::test]
async fn banned_and_normal_requests_return_before_mail_sends() {
    let Some(app) = common::setup(|_| {}).await else {
        return;
    };

    // 直接在库里标记封禁（走 HTTP 管理接口不影响本测试关注点）
    let banned_hmac = app.state.config.account_hmac("banned@qq.com");
    sqlx::query("INSERT INTO banned_accounts (email_hmac, reason) VALUES ($1, '测试封禁')")
        .bind(&banned_hmac)
        .execute(&app.state.pool)
        .await
        .expect("建立封禁失败");

    const DELAY_MS: u64 = 500;
    // 阈值给足余量：本地往返在负载下也远小于发信延迟
    const BUDGET_MS: u128 = 300;
    app.mailer.set_delay_ms(DELAY_MS);

    let banned_elapsed = {
        let start = std::time::Instant::now();
        let response = app.request_key("banned@qq.com").await;
        assert_eq!(response.status(), 202);
        start.elapsed().as_millis()
    };
    let normal_elapsed = {
        let start = std::time::Instant::now();
        let response = app.request_key("normal@qq.com").await;
        assert_eq!(response.status(), 202);
        start.elapsed().as_millis()
    };
    assert!(
        banned_elapsed < BUDGET_MS,
        "封禁邮箱返回过慢：{banned_elapsed}ms"
    );
    assert!(
        normal_elapsed < BUDGET_MS,
        "正常邮箱返回过慢：{normal_elapsed}ms"
    );

    // 返回时邮件都还没记录
    assert!(
        app.mailer.mails().await.is_empty(),
        "响应返回时后台发信不应已完成"
    );

    // 后台任务结束后：正常邮箱 1 封，封禁邮箱 0 封
    app.wait_mail_tasks().await;
    let mails = app.mailer.mails().await;
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0].to, "normal@qq.com");
}

/// 发信失败只记日志：验证记录保留（冷却仍然生效），响应仍为 202。
#[tokio::test]
async fn background_send_failure_keeps_verification_record() {
    let Some(app) = common::setup(|_| {}).await else {
        return;
    };
    app.mailer.set_fail(true);
    assert_eq!(app.request_key("fail@qq.com").await.status(), 202);
    app.wait_mail_tasks().await;
    assert!(app.mailer.mails().await.is_empty(), "失败的发送不应记录");
    // 记录仍在：冷却窗口内再申请得到 429
    assert_eq!(app.request_key("fail@qq.com").await.status(), 429);
}
