//! 目录快照：全部 published 模板的确定性 JSON 包，gzip 后原子落盘。

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::body::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Serialize;
use tokio::sync::{Mutex, Notify};

use crate::error::ApiError;
use crate::models::{TemplateJson, TemplatePackage, TemplateRow, PACKAGE_FORMAT, PACKAGE_VERSION};

const SEL_ALL_PUBLISHED_ORDERED: &str = "SELECT id, name, ai_description, content, defaults, reference, tags, author, owner_key_id, owner_email_hmac, status, version, created_at, updated_at FROM templates WHERE status = 'published' ORDER BY id";

/// 生成失败后重试前的等待时间，避免数据库故障时空转。
const RETRY_DELAY: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct CatalogMeta {
    /// 未压缩 JSON 的 SHA-256 十六进制。
    pub hash: String,
    pub count: usize,
    /// 模板最大更新时间（非生成时刻）。
    pub updated_at: String,
    /// gzip 后字节数。
    pub size: u64,
}

/// 明文与 gzip 字节、元数据放在同一个 Arc 里整体替换：接口取一次快照，
/// ETag 与正文必然来自同一次生成；两种编码的 ETag 哈希部分相同。
pub struct CatalogSnapshot {
    pub meta: CatalogMeta,
    pub plain: Bytes,
    pub gzipped: Bytes,
}

#[derive(Clone)]
pub struct Catalog {
    state: Arc<CatalogState>,
}

struct CatalogState {
    /// 只在取放 Arc 的瞬间持锁，不跨 await。
    snapshot: RwLock<Option<Arc<CatalogSnapshot>>>,
    /// 生成过程串行化，避免并发 regenerate 相互覆盖。
    regen_lock: Mutex<()>,
    dirty: AtomicBool,
    notify: Notify,
    catalog_dir: PathBuf,
}

impl Catalog {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            state: Arc::new(CatalogState {
                snapshot: RwLock::new(None),
                regen_lock: Mutex::new(()),
                dirty: AtomicBool::new(false),
                notify: Notify::new(),
                catalog_dir: data_dir.join("catalog"),
            }),
        }
    }

    /// 当前内存快照（元数据与正文来自同一次生成）。
    pub fn snapshot(&self) -> Option<Arc<CatalogSnapshot>> {
        self.state
            .snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn meta(&self) -> Option<CatalogMeta> {
        self.snapshot().map(|snapshot| snapshot.meta.clone())
    }

    pub fn mark_dirty(&self) {
        self.state.dirty.store(true, Ordering::SeqCst);
        self.state.notify.notify_one();
    }

    pub fn is_dirty(&self) -> bool {
        self.state.dirty.load(Ordering::SeqCst)
    }

    /// 从数据库重新生成快照。
    pub async fn regenerate(&self, pool: &sqlx::PgPool) -> Result<CatalogMeta, ApiError> {
        self.regenerate_with(|| fetch_published(pool)).await
    }

    /// 生成的核心流程，数据来源由 `load` 提供（测试可注入读库期间的并发改动）。
    ///
    /// 先清脏标记再读数据：读取期间发生的改动会重新置脏，留给下一轮，不会丢；
    /// 生成失败时把脏标记恢复，等待重试。
    pub async fn regenerate_with<F, Fut>(&self, load: F) -> Result<CatalogMeta, ApiError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<TemplateRow>, ApiError>>,
    {
        let _serial = self.state.regen_lock.lock().await;
        self.state.dirty.store(false, Ordering::SeqCst);

        let snapshot = match load().await.and_then(|rows| build_snapshot(&rows)) {
            Ok(snapshot) => Arc::new(snapshot),
            Err(error) => {
                self.state.dirty.store(true, Ordering::SeqCst);
                return Err(error);
            }
        };
        let meta = snapshot.meta.clone();
        let gzipped = snapshot.gzipped.clone();
        *self
            .state
            .snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(snapshot);

        // 磁盘只是落盘副本：失败只记日志，内存快照已经生效
        if let Err(error) = write_atomic(&self.state.catalog_dir, &gzipped).await {
            tracing::error!(error = ?error, "目录快照落盘失败（内存快照已更新）");
        }
        Ok(meta)
    }
}

async fn fetch_published(pool: &sqlx::PgPool) -> Result<Vec<TemplateRow>, ApiError> {
    Ok(sqlx::query_as(SEL_ALL_PUBLISHED_ORDERED)
        .fetch_all(pool)
        .await?)
}

fn build_snapshot(rows: &[TemplateRow]) -> Result<CatalogSnapshot, ApiError> {
    let package = build_package(rows);
    let json = serde_json::to_vec(&package)
        .map_err(|e| ApiError::internal_with(format!("快照序列化失败：{e}")))?;
    let gzipped = gzip_bytes(&json);
    Ok(CatalogSnapshot {
        meta: CatalogMeta {
            hash: crate::crypto::sha256_hex(&json),
            count: rows.len(),
            updated_at: package.updated_at,
            size: gzipped.len() as u64,
        },
        plain: Bytes::from(json),
        gzipped: Bytes::from(gzipped),
    })
}

/// 组装 JSON 包。字段顺序由结构体定义固定，保证同内容同哈希。
pub fn build_package(rows: &[TemplateRow]) -> TemplatePackage {
    let max_updated = rows.iter().map(|row| row.updated_at).max();
    let updated_at = max_updated
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
        .unwrap_or_else(|| "1970-01-01T00:00:00.000000Z".to_string());
    TemplatePackage {
        format: PACKAGE_FORMAT.to_string(),
        version: PACKAGE_VERSION,
        updated_at,
        templates: rows.iter().cloned().map(TemplateJson::from).collect(),
    }
}

fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    std::io::Write::write_all(&mut encoder, data).expect("内存写入不会失败");
    encoder.finish().expect("gzip 压缩不会失败")
}

async fn write_atomic(catalog_dir: &Path, bytes: &[u8]) -> Result<(), ApiError> {
    tokio::fs::create_dir_all(catalog_dir)
        .await
        .map_err(|e| ApiError::internal_with(format!("创建快照目录失败：{e}")))?;
    let final_path = catalog_dir.join("catalog.json.gz");
    let tmp_path = catalog_dir.join("catalog.json.gz.tmp");
    tokio::fs::write(&tmp_path, bytes)
        .await
        .map_err(|e| ApiError::internal_with(format!("写入快照临时文件失败：{e}")))?;
    tokio::fs::rename(&tmp_path, &final_path)
        .await
        .map_err(|e| ApiError::internal_with(format!("快照文件改名失败：{e}")))?;
    Ok(())
}

/// 后台任务：数据变动后按 debounce 合并重新生成，失败时延迟重试。
pub fn spawn_worker(catalog: Catalog, pool: sqlx::PgPool, debounce_secs: u64) {
    tokio::spawn(async move {
        loop {
            catalog.state.notify.notified().await;
            tokio::time::sleep(Duration::from_secs(debounce_secs)).await;
            if !catalog.is_dirty() {
                continue;
            }
            match catalog.regenerate(&pool).await {
                Ok(meta) => {
                    tracing::info!(hash = %meta.hash, count = meta.count, "目录快照已更新")
                }
                Err(error) => {
                    tracing::error!(error = ?error, "目录快照生成失败，稍后重试");
                    tokio::time::sleep(RETRY_DELAY).await;
                    catalog.state.notify.notify_one();
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use chrono::Utc;
    use std::io::Read;
    use uuid::Uuid;

    fn row(id: &str, updated_at: chrono::DateTime<Utc>) -> TemplateRow {
        TemplateRow {
            id: id.to_string(),
            name: format!("模板{id}"),
            ai_description: "说明".to_string(),
            content: "内容 {{input}}".to_string(),
            defaults: serde_json::json!({}),
            reference: "none".to_string(),
            tags: vec!["标签".to_string()],
            author: None,
            owner_key_id: Uuid::new_v4(),
            owner_email_hmac: "hmac-test".to_string(),
            status: "published".to_string(),
            version: 1,
            created_at: updated_at,
            updated_at,
        }
    }

    fn gunzip(bytes: &[u8]) -> Vec<u8> {
        let mut plain = Vec::new();
        flate2::read::GzDecoder::new(bytes)
            .read_to_end(&mut plain)
            .expect("快照应是合法 gzip");
        plain
    }

    #[test]
    fn package_deterministic_hash() {
        let t1 = Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2026, 10, 2, 8, 30, 0).unwrap();
        let rows = vec![row("b", t1), row("a", t2)];
        let json1 = serde_json::to_vec(&build_package(&rows)).unwrap();
        // 行序打乱后（快照生成按 id 排序，此处模拟同一输入）哈希一致
        let json2 =
            serde_json::to_vec(&build_package(&[rows[0].clone(), rows[1].clone()])).unwrap();
        assert_eq!(
            crate::crypto::sha256_hex(&json1),
            crate::crypto::sha256_hex(&json2)
        );
        // 内容变化则哈希变化
        let mut changed = rows.clone();
        changed[0].name = "改名".to_string();
        let json3 = serde_json::to_vec(&build_package(&changed)).unwrap();
        assert_ne!(
            crate::crypto::sha256_hex(&json1),
            crate::crypto::sha256_hex(&json3)
        );
        // updated_at 取最大值而不是生成时刻
        let package = build_package(&rows);
        assert_eq!(
            package.updated_at,
            t2.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
        );
        assert_eq!(package.format, "gemini-image-templates");
        assert_eq!(package.version, 1);
    }

    #[test]
    fn empty_package_has_epoch_updated_at() {
        let package = build_package(&[]);
        assert_eq!(package.updated_at, "1970-01-01T00:00:00.000000Z");
        assert!(package.templates.is_empty());
    }

    #[test]
    fn field_order_fixed_in_json() {
        // serde_json::Value 会按字母排序键，这里用序列化字节验证字段顺序
        let t = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
        let json = serde_json::to_string(&build_package(&[row("a", t)])).unwrap();
        // 只检查模板对象内部的字段顺序（包级别也有 version/updated_at）
        let json = &json[json.find("\"templates\":").expect("缺少 templates")..];
        let order = [
            "id",
            "name",
            "ai_description",
            "content",
            "defaults",
            "reference",
            "tags",
            "version",
            "created_at",
            "updated_at",
        ];
        let mut last = 0;
        for key in order {
            let needle = format!("\"{key}\":");
            let pos = json
                .find(&needle)
                .unwrap_or_else(|| panic!("缺少字段 {key}"));
            assert!(pos > last, "字段 {key} 顺序错误：{json}");
            last = pos;
        }
    }

    #[tokio::test]
    async fn snapshot_pairs_meta_with_body_and_disk_copy() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::new(dir.path());
        assert!(catalog.snapshot().is_none());

        let t = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
        let rows = vec![row("a", t), row("b", t)];
        let meta = catalog
            .regenerate_with(|| async { Ok(rows) })
            .await
            .unwrap();

        let snapshot = catalog.snapshot().expect("应已生成快照");
        assert_eq!(snapshot.meta, meta);
        assert_eq!(meta.count, 2);
        assert_eq!(meta.size, snapshot.gzipped.len() as u64);
        assert_eq!(
            crate::crypto::sha256_hex(&gunzip(&snapshot.gzipped)),
            meta.hash,
            "ETag 对应的哈希必须是正文的哈希"
        );
        let on_disk = std::fs::read(dir.path().join("catalog/catalog.json.gz")).unwrap();
        assert_eq!(on_disk, snapshot.gzipped.as_ref(), "磁盘副本应与内存一致");
        assert!(
            !dir.path().join("catalog/catalog.json.gz.tmp").exists(),
            "临时文件应已改名"
        );
    }

    #[tokio::test]
    async fn same_content_generated_twice_has_same_hash() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::new(dir.path());
        let t = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
        let first = catalog
            .regenerate_with(|| async { Ok(vec![row("a", t)]) })
            .await
            .unwrap();
        let second = catalog
            .regenerate_with(|| async { Ok(vec![row("a", t)]) })
            .await
            .unwrap();
        assert_eq!(first, second);
    }

    /// 生成期间发生的改动（此处在读库回调里置脏）必须留到下一轮，不能被生成结束时的清标记吞掉。
    #[tokio::test]
    async fn change_during_generation_is_not_lost() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::new(dir.path());
        let t = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();

        catalog.mark_dirty();
        catalog
            .regenerate_with(|| async {
                assert!(!catalog.is_dirty(), "读库之前应已取走脏标记");
                // 模拟读库期间另一个请求提交了改动
                catalog.mark_dirty();
                Ok(vec![row("a", t)])
            })
            .await
            .unwrap();
        assert!(catalog.is_dirty(), "读库期间的改动应保持脏标记，等待下一轮");

        // 下一轮没有新改动，生成后标记清除
        catalog
            .regenerate_with(|| async { Ok(vec![row("a", t), row("b", t)]) })
            .await
            .unwrap();
        assert!(!catalog.is_dirty());
        assert_eq!(catalog.meta().unwrap().count, 2);
    }

    #[tokio::test]
    async fn failed_generation_restores_dirty_and_keeps_old_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::new(dir.path());
        let t = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
        let good = catalog
            .regenerate_with(|| async { Ok(vec![row("a", t)]) })
            .await
            .unwrap();

        catalog.mark_dirty();
        let result = catalog
            .regenerate_with(|| async { Err(ApiError::internal()) })
            .await;
        assert!(result.is_err());
        assert!(catalog.is_dirty(), "失败后必须恢复脏标记");
        assert_eq!(catalog.meta().unwrap(), good, "失败不应破坏旧快照");
    }
}
