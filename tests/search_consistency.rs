//! 检索索引与数据库的一致性（需要数据库；未设置 DATABASE_URL 时跳过）。
//!
//! 索引以数据库为准：启动时整体重建；增量提交只传模板 ID，提交时读库里的当前状态，
//! 不被乱序或过期的变更覆盖。

mod common;

use image_prompt_hub::search::{IndexOp, SearchIndex};

/// 直接往库里写一条模板（绕过 API，索引不知情）。
async fn insert_template(
    app: &common::TestApp,
    owner: &str,
    id: &str,
    name: &str,
    content: &str,
    status: &str,
) {
    let email_hmac = app.state.config.account_hmac(owner);
    let key_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM api_keys WHERE email_hmac = $1 LIMIT 1")
            .bind(&email_hmac)
            .fetch_one(&app.state.pool)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO templates (id, name, content, owner_key_id, owner_email_hmac, status)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(name)
    .bind(content)
    .bind(key_id)
    .bind(email_hmac)
    .bind(status)
    .execute(&app.state.pool)
    .await
    .unwrap();
}

fn hit_ids(index: &SearchIndex, query: &str) -> Vec<String> {
    index
        .search(query, None, 0, 50)
        .unwrap()
        .hits
        .into_iter()
        .map(|(id, _)| id)
        .collect()
}

async fn wait_for_hits(index: &SearchIndex, query: &str, id: &str, expect_found: bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if hit_ids(index, query).iter().any(|hit| hit == id) == expect_found {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "等待索引收敛超时：q={query} id={id} 期望出现={expect_found}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// 全量重建不比对数量。内容变了、状态变了、总数没变，重建后索引也与库完全一致。
#[tokio::test]
async fn rebuild_follows_database_even_when_document_count_is_unchanged() {
    let Some(app) = common::setup(|_| {}).await else {
        return;
    };
    app.create_key_direct("idx@qq.com", &["read", "write"])
        .await;
    insert_template(
        &app,
        "idx@qq.com",
        "aaaaaaaaaaa1",
        "甲模板",
        "原始内容 alpha",
        "published",
    )
    .await;
    insert_template(
        &app,
        "idx@qq.com",
        "aaaaaaaaaaa2",
        "乙模板",
        "另一份 beta",
        "published",
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    let (index, _queue) = SearchIndex::open_dir(&dir.path().join("index")).unwrap();
    index.rebuild_from_db(&app.state.pool).await.unwrap();
    assert_eq!(index.doc_count(), 2);
    assert_eq!(hit_ids(&index, "alpha"), ["aaaaaaaaaaa1"]);

    // 改内容、隐藏一条、新增一条：总数仍然是 2
    sqlx::query("UPDATE templates SET content = '全新的内容 gamma' WHERE id = 'aaaaaaaaaaa1'")
        .execute(&app.state.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE templates SET status = 'hidden' WHERE id = 'aaaaaaaaaaa2'")
        .execute(&app.state.pool)
        .await
        .unwrap();
    insert_template(
        &app,
        "idx@qq.com",
        "aaaaaaaaaaa3",
        "丙模板",
        "第三份 delta",
        "published",
    )
    .await;

    index.rebuild_from_db(&app.state.pool).await.unwrap();
    assert_eq!(index.doc_count(), 2, "数量没变，内容必须仍然跟上数据库");
    assert!(hit_ids(&index, "alpha").is_empty(), "旧内容不应再命中");
    assert_eq!(hit_ids(&index, "gamma"), ["aaaaaaaaaaa1"]);
    assert!(hit_ids(&index, "beta").is_empty(), "已隐藏的模板不应命中");
    assert_eq!(hit_ids(&index, "delta"), ["aaaaaaaaaaa3"]);
}

/// 提交时按 ID 读库里的当前状态，不受变更类型和顺序影响。
#[tokio::test]
async fn flush_uses_current_database_state() {
    let Some(app) = common::setup(|_| {}).await else {
        return;
    };
    app.create_key_direct("flush@qq.com", &["read", "write"])
        .await;
    insert_template(
        &app,
        "flush@qq.com",
        "bbbbbbbbbbb1",
        "公开模板",
        "公开内容 epsilon",
        "published",
    )
    .await;
    insert_template(
        &app,
        "flush@qq.com",
        "bbbbbbbbbbb2",
        "隐藏模板",
        "隐藏内容 zeta",
        "hidden",
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    let (index, _queue) = SearchIndex::open_dir(&dir.path().join("index")).unwrap();
    let ids = |list: &[&str]| list.iter().map(|id| id.to_string()).collect::<Vec<_>>();

    // 对已隐藏的模板“写入”：库里不是 published，不会进索引
    index
        .flush_ids(&app.state.pool, &ids(&["bbbbbbbbbbb2"]))
        .await
        .unwrap();
    assert!(hit_ids(&index, "zeta").is_empty());

    // 对仍然公开的模板“删除”：库里是 published，索引里保留它
    index
        .flush_ids(&app.state.pool, &ids(&["bbbbbbbbbbb1"]))
        .await
        .unwrap();
    assert_eq!(hit_ids(&index, "epsilon"), ["bbbbbbbbbbb1"]);

    // 同一个 ID 反复同步不产生重复文档
    for _ in 0..3 {
        index
            .flush_ids(&app.state.pool, &ids(&["bbbbbbbbbbb1", "bbbbbbbbbbb1"]))
            .await
            .unwrap();
    }
    assert_eq!(index.doc_count(), 1);

    // 库里状态变化后再同步：新内容替换旧内容，删除的模板从索引消失
    sqlx::query("UPDATE templates SET content = '更新后的内容 eta' WHERE id = 'bbbbbbbbbbb1'")
        .execute(&app.state.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE templates SET status = 'published' WHERE id = 'bbbbbbbbbbb2'")
        .execute(&app.state.pool)
        .await
        .unwrap();
    index
        .flush_ids(&app.state.pool, &ids(&["bbbbbbbbbbb1", "bbbbbbbbbbb2"]))
        .await
        .unwrap();
    assert!(hit_ids(&index, "epsilon").is_empty());
    assert_eq!(hit_ids(&index, "eta"), ["bbbbbbbbbbb1"]);
    assert_eq!(hit_ids(&index, "zeta"), ["bbbbbbbbbbb2"]);
    sqlx::query("UPDATE templates SET status = 'deleted' WHERE id = 'bbbbbbbbbbb1'")
        .execute(&app.state.pool)
        .await
        .unwrap();
    index
        .flush_ids(&app.state.pool, &ids(&["bbbbbbbbbbb1"]))
        .await
        .unwrap();
    assert!(hit_ids(&index, "eta").is_empty());
    assert_eq!(index.doc_count(), 1);
}

/// 后台提交任务端到端——队列里的变更类型（Upsert/Delete）与库里的真实状态不符时，以库为准。
#[tokio::test]
async fn background_worker_converges_to_database_state() {
    let Some(app) = common::setup(|_| {}).await else {
        return;
    };
    app.create_key_direct("worker@qq.com", &["read", "write"])
        .await;
    let dir = tempfile::tempdir().unwrap();
    let index = SearchIndex::open(&dir.path().join("index"), &app.state.pool)
        .await
        .unwrap();
    assert_eq!(index.doc_count(), 0);

    insert_template(
        &app,
        "worker@qq.com",
        "ccccccccccc1",
        "后台任务",
        "后台内容 theta",
        "published",
    )
    .await;
    index.submit(IndexOp::Upsert("ccccccccccc1".to_string()));
    wait_for_hits(&index, "theta", "ccccccccccc1", true).await;

    // 库里已隐藏，但队列里到达的是一条陈旧的 Upsert：以库为准，删除
    sqlx::query("UPDATE templates SET status = 'hidden' WHERE id = 'ccccccccccc1'")
        .execute(&app.state.pool)
        .await
        .unwrap();
    index.submit(IndexOp::Upsert("ccccccccccc1".to_string()));
    wait_for_hits(&index, "theta", "ccccccccccc1", false).await;

    // 库里重新公开，队列里却是 Delete：仍以库为准，写入
    sqlx::query("UPDATE templates SET status = 'published' WHERE id = 'ccccccccccc1'")
        .execute(&app.state.pool)
        .await
        .unwrap();
    index.submit(IndexOp::Delete("ccccccccccc1".to_string()));
    wait_for_hits(&index, "theta", "ccccccccccc1", true).await;
}

/// 读库失败时 flush 返回错误且不改动索引，数据库恢复后再同步即可补上。
#[tokio::test]
async fn failed_flush_leaves_the_index_untouched() {
    let Some(app) = common::setup(|_| {}).await else {
        return;
    };
    app.create_key_direct("retry-idx@qq.com", &["read", "write"])
        .await;
    insert_template(
        &app,
        "retry-idx@qq.com",
        "ddddddddddd1",
        "重试模板",
        "重试内容 iota",
        "published",
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    let (index, _queue) = SearchIndex::open_dir(&dir.path().join("index")).unwrap();

    // 一个已关闭的连接池：读库必然失败
    let closed = sqlx::PgPool::connect_lazy(&app.state.config.secrets.database_url).unwrap();
    closed.close().await;
    let result = index
        .flush_ids(&closed, &["ddddddddddd1".to_string()])
        .await;
    assert!(result.is_err(), "读库失败时 flush 应报错");
    assert_eq!(index.doc_count(), 0);

    index
        .flush_ids(&app.state.pool, &["ddddddddddd1".to_string()])
        .await
        .unwrap();
    assert_eq!(hit_ids(&index, "iota"), ["ddddddddddd1"]);
}

/// 后台任务提交失败时保留待处理的 ID，数据库恢复后在下一个窗口自动补上，变更不会永久丢失。
#[tokio::test]
async fn background_worker_keeps_and_retries_failed_commits() {
    let Some(app) = common::setup(|_| {}).await else {
        return;
    };
    app.create_key_direct("retry-worker@qq.com", &["read", "write"])
        .await;
    let dir = tempfile::tempdir().unwrap();
    let index = SearchIndex::open(&dir.path().join("index"), &app.state.pool)
        .await
        .unwrap();
    insert_template(
        &app,
        "retry-worker@qq.com",
        "eeeeeeeeeee1",
        "重试任务",
        "重试任务内容 kappa",
        "published",
    )
    .await;

    // 让读库失败：把表暂时改名
    sqlx::query("ALTER TABLE templates RENAME TO templates_offline")
        .execute(&app.state.pool)
        .await
        .unwrap();
    index.submit(IndexOp::Upsert("eeeeeeeeeee1".to_string()));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while index.flush_failures() == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "后台任务应已尝试提交并失败"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(hit_ids(&index, "kappa").is_empty());

    // 恢复后无需再次提交变更，重试窗口会自行补上
    sqlx::query("ALTER TABLE templates_offline RENAME TO templates")
        .execute(&app.state.pool)
        .await
        .unwrap();
    wait_for_hits(&index, "kappa", "eeeeeeeeeee1", true).await;
}
