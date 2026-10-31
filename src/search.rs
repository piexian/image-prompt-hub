//! tantivy + jieba 的 BM25 检索：只索引 published 模板，写入走合并提交的后台任务。

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tantivy::collector::TopDocs;
use tantivy::query::{BooleanQuery, BoostQuery, EmptyQuery, Occur, Query, TermQuery};
use tantivy::schema::Value as DocumentValue;
use tantivy::schema::{
    Field, IndexRecordOption, Schema, TextFieldIndexing, TextOptions, STORED, STRING,
};
use tantivy::snippet::SnippetGenerator;
use tantivy::tokenizer::{LowerCaser, TextAnalyzer, TokenFilter};
use tantivy::{
    doc, Index, IndexReader, IndexWriter, ReloadPolicy, Score, TantivyDocument, TantivyError,
};
use tantivy_jieba::JiebaTokenizer;
use tokio::sync::mpsc;

use crate::error::{ApiError, ErrorCode};
use crate::models::TemplateRow;

const SEL_PUBLISHED_BY_IDS: &str = "SELECT id, name, ai_description, content, defaults, reference, tags, author, owner_key_id, owner_email_hmac, status, version, created_at, updated_at FROM templates WHERE status = 'published' AND id = ANY($1)";

const SEL_ALL_PUBLISHED: &str = "SELECT id, name, ai_description, content, defaults, reference, tags, author, owner_key_id, owner_email_hmac, status, version, created_at, updated_at FROM templates WHERE status = 'published' ORDER BY id";

/// 索引目录的版本，与磁盘上的版本文件不一致时清空目录重建。升级 tantivy 或改动字段结构时提高它：
/// 索引随时可以从数据库重建，不依赖新版本读取旧版本写出的文件。
const INDEX_VERSION: u32 = 2;
const WRITER_HEAP_BYTES: usize = 50 * 1024 * 1024;
/// 提交合并窗口：窗口内的多次变更一次 commit；提交失败时也以它为重试间隔。
const COMMIT_MERGE_WINDOW: Duration = Duration::from_secs(1);
/// 检索翻页上限。
pub const SEARCH_OFFSET_LIMIT: usize = 500;

#[derive(Clone, Copy)]
pub struct SearchFields {
    id: Field,
    name: Field,
    tags_text: Field,
    tags_kw: Field,
    description: Field,
    content: Field,
}

impl SearchFields {
    fn from_schema(schema: &Schema) -> Result<Self, ApiError> {
        let field = |name: &str| {
            schema
                .get_field(name)
                .map_err(|_| ApiError::internal_with(format!("索引结构缺少字段 {name}")))
        };
        Ok(Self {
            id: field("id")?,
            name: field("name")?,
            tags_text: field("tags_text")?,
            tags_kw: field("tags_kw")?,
            description: field("description")?,
            content: field("content")?,
        })
    }
}

fn build_schema() -> Schema {
    let mut builder = Schema::builder();
    let indexed_text = |builder: &mut tantivy::schema::SchemaBuilder, name: &str| {
        let indexing = TextFieldIndexing::default()
            .set_tokenizer("jieba")
            .set_index_option(IndexRecordOption::WithFreqsAndPositions);
        builder.add_text_field(name, TextOptions::default().set_indexing_options(indexing));
    };
    builder.add_text_field("id", STRING | STORED);
    indexed_text(&mut builder, "name");
    indexed_text(&mut builder, "tags_text");
    builder.add_text_field("tags_kw", STRING);
    indexed_text(&mut builder, "description");
    indexed_text(&mut builder, "content");
    builder.build()
}

fn register_tokenizer(index: &Index) {
    let tokenizer = LowerCaser.transform(JiebaTokenizer::new());
    index
        .tokenizers()
        .register("jieba", TextAnalyzer::from(tokenizer));
}

/// 检索结果：命中与片段生成器。
pub struct SearchOutcome {
    pub hits: Vec<(String, Score)>,
    pub generator: Option<SnippetGenerator>,
}

impl SearchOutcome {
    /// 用正文生成 ≤120 字的纯文本命中片段。
    pub fn snippet(&self, content: &str) -> Option<String> {
        let generator = self.generator.as_ref()?;
        Some(
            generator
                .snippet(content)
                .fragment()
                .chars()
                .take(120)
                .collect(),
        )
    }
}

/// 待提交变更只携带模板 ID：提交时按数据库当前状态决定写入或删除，
/// 避免乱序的旧内容覆盖新状态。
#[derive(Debug)]
pub enum IndexOp {
    Upsert(String),
    Delete(String),
}

impl IndexOp {
    fn into_id(self) -> String {
        match self {
            Self::Upsert(id) | Self::Delete(id) => id,
        }
    }
}

#[derive(Clone)]
pub struct SearchIndex {
    inner: Arc<IndexInner>,
}

struct IndexInner {
    reader: IndexReader,
    fields: SearchFields,
    ops: mpsc::UnboundedSender<IndexOp>,
    /// 常驻写入器；全量重建与增量提交共用，避免目录锁冲突。
    writer: Arc<Mutex<IndexWriter>>,
    /// 后台提交失败的累计次数（失败后会在下个窗口重试）。
    flush_failures: Arc<AtomicU64>,
}

impl SearchIndex {
    /// 打开索引并按数据库全量重建，再启动后台提交任务。
    /// 每次启动都整体重建：模板量不大，重建很快，能消除“内容变了但数量没变”的漂移。
    pub async fn open(index_dir: &Path, pool: &sqlx::PgPool) -> Result<Self, ApiError> {
        let (index, rx) = Self::open_dir(index_dir)?;
        index.rebuild_from_db(pool).await?;
        tokio::spawn(commit_worker(
            index.inner.writer.clone(),
            index.inner.reader.clone(),
            index.inner.fields,
            index.inner.flush_failures.clone(),
            pool.clone(),
            rx,
        ));
        Ok(index)
    }

    /// 准备索引目录并拿到写锁，不读数据库。结构版本不符时清空目录重建。
    /// 另一个进程（通常是正在运行的服务）持有写锁时返回明确的提示。
    pub fn open_dir(
        index_dir: &Path,
    ) -> Result<(Self, mpsc::UnboundedReceiver<IndexOp>), ApiError> {
        let version_path = index_dir.join("iph-index-version.json");
        let version_ok = std::fs::read_to_string(&version_path)
            .ok()
            .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
            .and_then(|value| value.get("version").and_then(|v| v.as_u64()))
            .is_some_and(|version| version == u64::from(INDEX_VERSION));

        if !version_ok {
            if index_dir.exists() {
                std::fs::remove_dir_all(index_dir)
                    .map_err(|e| ApiError::internal_with(format!("清理旧索引失败：{e}")))?;
            }
            std::fs::create_dir_all(index_dir)
                .map_err(|e| ApiError::internal_with(format!("创建索引目录失败：{e}")))?;
            std::fs::write(
                &version_path,
                serde_json::json!({"version": INDEX_VERSION}).to_string(),
            )
            .map_err(|e| ApiError::internal_with(format!("写入索引元数据失败：{e}")))?;
        }

        let index = if version_ok && index_dir.join("meta.json").exists() {
            Index::open_in_dir(index_dir)
                .map_err(|e| ApiError::internal_with(format!("打开索引失败：{e}")))?
        } else {
            Index::create_in_dir(index_dir, build_schema())
                .map_err(|e| ApiError::internal_with(format!("创建索引失败：{e}")))?
        };
        Self::assemble(index)
    }

    fn assemble(index: Index) -> Result<(Self, mpsc::UnboundedReceiver<IndexOp>), ApiError> {
        register_tokenizer(&index);
        let fields = SearchFields::from_schema(&index.schema())?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()
            .map_err(|e| ApiError::internal_with(format!("创建索引读取器失败：{e}")))?;
        let writer = index
            .writer(WRITER_HEAP_BYTES)
            .map_err(|error| match error {
                // 提示直接面向命令行使用者，不走 internal_with 以免被替换成通用文案
                TantivyError::LockFailure(..) => ApiError::new(
                    ErrorCode::Internal,
                    "检索索引正被其他进程占用（服务正在运行？），请先停止服务",
                ),
                other => ApiError::internal_with(format!("创建索引写入器失败：{other}")),
            })?;

        let (ops, rx) = mpsc::unbounded_channel();
        Ok((
            Self {
                inner: Arc::new(IndexInner {
                    reader,
                    fields,
                    ops,
                    writer: Arc::new(Mutex::new(writer)),
                    flush_failures: Arc::new(AtomicU64::new(0)),
                }),
            },
            rx,
        ))
    }

    /// 变更加入待提交队列，由后台任务合并提交。
    pub fn submit(&self, op: IndexOp) {
        if self.inner.ops.send(op).is_err() {
            tracing::error!("索引提交任务已退出，变更未入队");
        }
    }

    /// 按数据库全量重建（启动与 reindex 子命令共用）。
    pub async fn rebuild_from_db(&self, pool: &sqlx::PgPool) -> Result<(), ApiError> {
        let rows: Vec<TemplateRow> = sqlx::query_as(SEL_ALL_PUBLISHED).fetch_all(pool).await?;
        tracing::info!(count = rows.len(), "重建检索索引");
        self.reindex_with(rows)
    }

    /// 复用常驻写入器删除全部文档后重写。
    pub fn reindex_with(&self, rows: Vec<TemplateRow>) -> Result<(), ApiError> {
        let mut guard = self
            .inner
            .writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let result: Result<(), ApiError> = (|| {
            guard
                .delete_all_documents()
                .map_err(|e| ApiError::internal_with(format!("清空索引失败：{e}")))?;
            for row in &rows {
                add_row(&mut guard, &self.inner.fields, row)?;
            }
            guard
                .commit()
                .map_err(|e| ApiError::internal_with(format!("索引提交失败：{e}")))?;
            Ok(())
        })();
        if result.is_err() {
            // 丢弃已暂存的操作，避免半成品被下一次提交带出去
            let _ = guard.rollback();
        }
        drop(guard);
        result?;
        self.inner
            .reader
            .reload()
            .map_err(|e| ApiError::internal_with(format!("刷新索引读取器失败：{e}")))
    }

    /// 按数据库当前状态同步给定模板：published 写入，其余删除。
    /// 后台提交任务与测试共用同一条路径。
    pub async fn flush_ids(&self, pool: &sqlx::PgPool, ids: &[String]) -> Result<(), ApiError> {
        flush_ids(
            &self.inner.writer,
            &self.inner.reader,
            self.inner.fields,
            pool,
            ids,
        )
        .await
    }

    /// BM25 检索。返回命中（模板 ID、分数）与正文片段生成器；
    /// 正文不入索引存储，片段由调用方用数据库里的正文生成。
    pub fn search(
        &self,
        query_text: &str,
        tag: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<SearchOutcome, ApiError> {
        if limit == 0 || offset >= SEARCH_OFFSET_LIMIT || query_text.trim().is_empty() {
            return Ok(SearchOutcome {
                hits: Vec::new(),
                generator: None,
            });
        }
        let query = self.build_query(query_text, tag)?;
        let searcher = self.inner.reader.searcher();
        // with_limit 是“跳过 offset 条之后取多少条”，翻页总深度不超过上限
        let page_size = limit.min(SEARCH_OFFSET_LIMIT - offset);
        let top_docs = searcher
            .search(
                &query,
                &TopDocs::with_limit(page_size)
                    .and_offset(offset)
                    .order_by_score(),
            )
            .map_err(|e| ApiError::internal_with(format!("检索失败：{e}")))?;

        let mut generator = SnippetGenerator::create(&searcher, &query, self.inner.fields.content)
            .map_err(|e| ApiError::internal_with(format!("创建片段生成器失败：{e}")))?;
        generator.set_max_num_chars(120);

        let mut hits = Vec::with_capacity(top_docs.len());
        for (score, doc_address) in top_docs {
            let doc: TantivyDocument = searcher
                .doc(doc_address)
                .map_err(|e| ApiError::internal_with(format!("读取索引文档失败：{e}")))?;
            let Some(id_value) = doc.get_first(self.inner.fields.id) else {
                continue;
            };
            let Some(id) = DocumentValue::as_str(&id_value) else {
                continue;
            };
            hits.push((id.to_string(), score));
        }
        Ok(SearchOutcome {
            hits,
            generator: Some(generator),
        })
    }

    /// 查询构造：jieba 分词（英文转小写）后按「字段加权 TermQuery 的 OR」组装，
    /// 用户输入不经过查询语法解析，天然容错。
    fn build_query(&self, query_text: &str, tag: Option<&str>) -> Result<Box<dyn Query>, ApiError> {
        let fields = self.inner.fields;
        let boosted_fields: [(Field, Score); 4] = [
            (fields.name, 3.0),
            (fields.tags_text, 2.0),
            (fields.description, 1.5),
            (fields.content, 1.0),
        ];
        let mut clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
        for token in tokenize_keywords(query_text) {
            for (field, boost) in boosted_fields {
                let term = tantivy::Term::from_field_text(field, &token);
                let term_query = TermQuery::new(term, IndexRecordOption::WithFreqsAndPositions);
                clauses.push((
                    Occur::Should,
                    Box::new(BoostQuery::new(Box::new(term_query), boost)),
                ));
            }
        }
        if clauses.is_empty() {
            return Ok(Box::new(EmptyQuery));
        }
        let text_query: Box<dyn Query> = Box::new(BooleanQuery::new(clauses));
        match tag {
            Some(tag) if !tag.is_empty() => {
                let term = tantivy::Term::from_field_text(fields.tags_kw, tag);
                let tag_query = TermQuery::new(term, IndexRecordOption::Basic);
                Ok(Box::new(BooleanQuery::new(vec![
                    (Occur::Must, text_query),
                    (Occur::Must, Box::new(tag_query)),
                ])))
            }
            _ => Ok(text_query),
        }
    }

    /// 当前索引里的文档数。
    pub fn doc_count(&self) -> u64 {
        self.inner.reader.searcher().num_docs()
    }

    /// 后台提交失败的累计次数；失败的变更会保留并在下个窗口重试。
    pub fn flush_failures(&self) -> u64 {
        self.inner.flush_failures.load(Ordering::SeqCst)
    }
}

/// 用注册的 jieba 分词器切词并小写，过滤空白与标点，保持出现顺序去重。
fn tokenize_keywords(text: &str) -> Vec<String> {
    let tokenizer = LowerCaser.transform(JiebaTokenizer::new());
    let mut analyzer = TextAnalyzer::from(tokenizer);
    let mut stream = analyzer.token_stream(text);
    let mut tokens: Vec<String> = Vec::new();
    while let Some(token) = stream.next() {
        let token = token.text.trim().to_lowercase();
        if token.is_empty() || token.chars().all(|c| !c.is_alphanumeric()) {
            continue;
        }
        if !tokens.contains(&token) {
            tokens.push(token);
        }
    }
    tokens
}

fn add_row(
    writer: &mut IndexWriter,
    fields: &SearchFields,
    row: &TemplateRow,
) -> Result<(), ApiError> {
    let mut document = doc!(
        fields.id => row.id.clone(),
        fields.name => row.name.clone(),
        fields.tags_text => row.tags.join(" "),
        fields.description => row.ai_description.clone(),
        fields.content => row.content.clone(),
    );
    for tag in &row.tags {
        document.add_text(fields.tags_kw, tag);
    }
    writer
        .add_document(document)
        .map(|_| ())
        .map_err(|e| ApiError::internal_with(format!("索引文档写入失败：{e}")))
}

fn delete_row(writer: &mut IndexWriter, fields: &SearchFields, id: &str) {
    let term = tantivy::Term::from_field_text(fields.id, id);
    writer.delete_term(term);
}

/// 读数据库当前状态后一次提交：先删除再按需写入，同一 ID 的多次变更只看最终状态。
async fn flush_ids(
    writer: &Arc<Mutex<IndexWriter>>,
    reader: &IndexReader,
    fields: SearchFields,
    pool: &sqlx::PgPool,
    ids: &[String],
) -> Result<(), ApiError> {
    let rows: Vec<TemplateRow> = sqlx::query_as(SEL_PUBLISHED_BY_IDS)
        .bind(ids)
        .fetch_all(pool)
        .await?;
    let writer = writer.clone();
    let ids = ids.to_vec();
    tokio::task::spawn_blocking(move || -> Result<(), ApiError> {
        let mut guard = writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let result = (|| {
            for id in &ids {
                delete_row(&mut guard, &fields, id);
            }
            for row in &rows {
                add_row(&mut guard, &fields, row)?;
            }
            guard
                .commit()
                .map(|_| ())
                .map_err(|e| ApiError::internal_with(format!("索引提交失败：{e}")))
        })();
        if result.is_err() {
            let _ = guard.rollback();
        }
        result
    })
    .await
    .map_err(|e| ApiError::internal_with(format!("索引提交任务异常：{e}")))??;
    reader
        .reload()
        .map_err(|e| ApiError::internal_with(format!("刷新索引读取器失败：{e}")))
}

/// 后台提交任务：等第一条变更，合并窗口内的后续变更一起提交；
/// 提交失败时保留待处理的 ID，下一个窗口重试，索引不会因一次故障永久落后于数据库。
async fn commit_worker(
    writer: Arc<Mutex<IndexWriter>>,
    reader: IndexReader,
    fields: SearchFields,
    failures: Arc<AtomicU64>,
    pool: sqlx::PgPool,
    mut rx: mpsc::UnboundedReceiver<IndexOp>,
) {
    let mut pending: BTreeSet<String> = BTreeSet::new();
    loop {
        if pending.is_empty() {
            match rx.recv().await {
                Some(op) => {
                    pending.insert(op.into_id());
                }
                None => break,
            }
        }
        tokio::time::sleep(COMMIT_MERGE_WINDOW).await;
        while let Ok(op) = rx.try_recv() {
            pending.insert(op.into_id());
        }
        let ids: Vec<String> = pending.iter().cloned().collect();
        match flush_ids(&writer, &reader, fields, &pool, &ids).await {
            Ok(()) => pending.clear(),
            Err(error) => {
                failures.fetch_add(1, Ordering::SeqCst);
                tracing::error!(error = ?error, pending = pending.len(), "索引提交失败，下个窗口重试")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::TemplateRow;
    use chrono::Utc;
    use uuid::Uuid;

    fn row(id: &str, name: &str, tags: &[&str], description: &str, content: &str) -> TemplateRow {
        TemplateRow {
            id: id.to_string(),
            name: name.to_string(),
            ai_description: description.to_string(),
            content: content.to_string(),
            defaults: serde_json::json!({}),
            reference: "none".to_string(),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            author: None,
            owner_key_id: Uuid::new_v4(),
            owner_email_hmac: "hmac-test".to_string(),
            status: "published".to_string(),
            version: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// 内存索引：测试直接同步写入文档，不启动依赖数据库的后台提交任务。
    fn ram_index(rows: Vec<TemplateRow>) -> SearchIndex {
        let (index, _rx) = SearchIndex::assemble(Index::create_in_ram(build_schema())).unwrap();
        index.reindex_with(rows).unwrap();
        index
    }

    #[tokio::test]
    async fn chinese_and_english_search() {
        let index = ram_index(vec![
            row(
                "a",
                "赛博朋克城市",
                &["科幻"],
                "霓虹灯下的未来都市",
                "描绘一座赛博朋克风格的城市，霓虹灯与雨夜",
            ),
            row(
                "b",
                "水彩风景",
                &["风景"],
                "清新水彩",
                "一片安静的森林与溪流，水彩笔触",
            ),
        ]);
        // 中文命中
        let outcome = index.search("赛博朋克", None, 0, 10).unwrap();
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].0, "a");
        // 英文小写命中英文正文
        let index2 = ram_index(vec![
            row("a", "壁纸", &[], "", "a cyberpunk city wallpaper"),
            row("b", "风景", &[], "", "watercolor forest"),
        ]);
        let outcome = index2.search("cyberpunk", None, 0, 10).unwrap();
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].0, "a");
        // 大小写不敏感
        let outcome = index2.search("CyberPunk", None, 0, 10).unwrap();
        assert_eq!(outcome.hits.len(), 1);
        // 中文词搜中文正文
        let outcome = index.search("森林", None, 0, 10).unwrap();
        assert!(outcome.hits.iter().any(|(id, _)| id == "b"));
    }

    #[tokio::test]
    async fn name_boosted_over_content() {
        let index = ram_index(vec![
            row("content-hit", "普通名称", &[], "", "这里有赛博朋克正文"),
            row("name-hit", "赛博朋克专用", &[], "", "完全无关的正文内容"),
        ]);
        let outcome = index.search("赛博朋克", None, 0, 10).unwrap();
        assert!(outcome.hits.len() >= 2, "hits = {:?}", outcome.hits);
        assert_eq!(outcome.hits[0].0, "name-hit");
    }

    #[tokio::test]
    async fn tag_filter_and_offset_limit() {
        let index = ram_index(vec![
            row("a", "城市图片", &["科幻"], "", "城市"),
            row("b", "森林图片", &["风景"], "", "森林"),
            row("c", "海洋图片", &["风景"], "", "海洋"),
        ]);
        let outcome = index.search("图片", Some("风景"), 0, 10).unwrap();
        let ids: Vec<String> = outcome.hits.iter().map(|(id, _)| id.clone()).collect();
        assert!(
            ids.contains(&"b".to_string())
                && ids.contains(&"c".to_string())
                && !ids.contains(&"a".to_string())
        );
        // 翻页
        let page1 = index.search("图片", None, 0, 2).unwrap();
        assert_eq!(page1.hits.len(), 2);
        let page2 = index.search("图片", None, 2, 2).unwrap();
        assert_eq!(page2.hits.len(), 1);
        // 上限
        assert!(index.search("图片", None, 500, 10).unwrap().hits.is_empty());
        assert!(index.search("图片", None, 0, 0).unwrap().hits.is_empty());
    }

    /// 翻页每页恰好 limit 条、页与页之间不重叠，且总深度不超过 500。
    #[tokio::test]
    async fn pages_have_exactly_limit_hits_without_overlap() {
        let rows: Vec<TemplateRow> = (0..12)
            .map(|i| {
                row(
                    &format!("id{i:02}"),
                    "图片模板",
                    &[],
                    "",
                    &format!("图片 {i}"),
                )
            })
            .collect();
        let index = ram_index(rows);
        let mut seen = std::collections::HashSet::new();
        for (offset, expected) in [(0, 5), (5, 5), (10, 2)] {
            let page = index.search("图片", None, offset, 5).unwrap();
            assert_eq!(page.hits.len(), expected, "offset={offset}");
            for (id, _) in page.hits {
                assert!(seen.insert(id), "页与页之间不应重复");
            }
        }
        assert_eq!(seen.len(), 12);

        // 深度上限：550 条命中时，offset 490 只能再取到第 500 条
        let many: Vec<TemplateRow> = (0..550)
            .map(|i| row(&format!("m{i:03}"), "批量模板", &[], "", "批量 内容"))
            .collect();
        let index = ram_index(many);
        assert_eq!(index.search("批量", None, 490, 50).unwrap().hits.len(), 10);
        assert_eq!(index.search("批量", None, 0, 50).unwrap().hits.len(), 50);
        assert!(index.search("批量", None, 500, 50).unwrap().hits.is_empty());
    }

    #[tokio::test]
    async fn tolerant_query_parsing() {
        let index = ram_index(vec![row("a", "城市", &[], "", "城市夜景")]);
        // 含查询语法特殊字符的输入不报错
        assert!(index.search("城+市 AND (夜 OR 晚)^2", None, 0, 10).is_ok());
        assert!(index.search("\"未闭合", None, 0, 10).is_ok());
        assert!(index.search("city:name", None, 0, 10).is_ok());
    }

    #[tokio::test]
    async fn snippet_from_content() {
        let index = ram_index(vec![row(
            "a",
            "长文模板",
            &[],
            "",
            &format!(
                "{}关键的赛博朋克段落{}",
                "前缀".repeat(50),
                "后缀".repeat(50)
            ),
        )]);
        let content = format!(
            "{}关键的赛博朋克段落{}",
            "前缀".repeat(50),
            "后缀".repeat(50)
        );
        let outcome = index.search("赛博朋克", None, 0, 10).unwrap();
        assert_eq!(outcome.hits.len(), 1);
        let snippet = outcome.snippet(&content).unwrap();
        assert!(snippet.chars().count() <= 120, "片段过长：{snippet}");
        assert!(snippet.contains("赛博朋克"), "片段应包含命中词：{snippet}");
        // 未命中正文返回开头片段或空
        let miss = outcome.snippet("完全无关的内容");
        assert!(miss.is_none() || miss.as_deref().map(|s| s.chars().count() <= 120).unwrap());
    }

    #[test]
    fn keyword_tokenization() {
        let tokens = tokenize_keywords("赛博朋克 城市");
        assert!(tokens.contains(&"赛博".to_string()));
        assert!(tokens.contains(&"城市".to_string()));
        assert!(tokenize_keywords("CyberPunk CITY") == vec!["cyberpunk", "city"]);
        assert!(tokenize_keywords("，。！").is_empty());
        assert!(tokenize_keywords("   ").is_empty());
    }

    /// 服务运行时索引目录的写锁被占用：reindex 必须明确提示先停服务，而不是崩溃。
    #[test]
    fn second_opener_gets_clear_lock_error() {
        let dir = tempfile::tempdir().unwrap();
        let index_dir = dir.path().join("index");
        let (running, _rx) = SearchIndex::open_dir(&index_dir).unwrap();

        let error = SearchIndex::open_dir(&index_dir)
            .err()
            .expect("写锁被占用时第二次打开应失败");
        assert!(
            error.message.contains("请先停止服务"),
            "提示应告知先停服务：{}",
            error.message
        );

        // 释放后可以重新打开
        drop(running);
        assert!(SearchIndex::open_dir(&index_dir).is_ok());
    }

    /// 版本文件与当前版本不一致（例如升级 tantivy 之前写出的目录）：整个目录清空重建，
    /// 旧文件即使无法被新版本读取也不会让启动失败。
    #[test]
    fn stale_version_directory_is_wiped_and_recreated() {
        let dir = tempfile::tempdir().unwrap();
        let index_dir = dir.path().join("index");
        std::fs::create_dir_all(&index_dir).unwrap();
        std::fs::write(
            index_dir.join("iph-index-version.json"),
            serde_json::json!({"version": INDEX_VERSION - 1}).to_string(),
        )
        .unwrap();
        std::fs::write(index_dir.join("meta.json"), "不是合法的 tantivy 元数据").unwrap();
        std::fs::write(index_dir.join("leftover.bin"), b"junk").unwrap();

        let (index, _rx) =
            SearchIndex::open_dir(&index_dir).expect("版本不符时应清空目录重建，而不是打开失败");
        assert_eq!(index.doc_count(), 0);
        assert!(!index_dir.join("leftover.bin").exists(), "旧文件应被清掉");
        let written: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(index_dir.join("iph-index-version.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(written["version"], INDEX_VERSION);

        // 重建后的目录可以正常写入和检索
        index
            .reindex_with(vec![row("a", "新目录", &[], "", "rebuilt")])
            .unwrap();
        assert_eq!(index.search("rebuilt", None, 0, 10).unwrap().hits.len(), 1);
    }

    #[test]
    fn reopening_keeps_on_disk_documents_until_rebuilt() {
        let dir = tempfile::tempdir().unwrap();
        let index_dir = dir.path().join("index");
        {
            let (index, _rx) = SearchIndex::open_dir(&index_dir).unwrap();
            index
                .reindex_with(vec![row("a", "旧模板", &[], "", "legacyword")])
                .unwrap();
            assert_eq!(index.doc_count(), 1);
        }
        let (reopened, _rx) = SearchIndex::open_dir(&index_dir).unwrap();
        // 结构版本一致时磁盘内容保留；启动路径随后会按数据库整体重建
        reopened.inner.reader.reload().unwrap();
        assert_eq!(reopened.doc_count(), 1);
        assert_eq!(
            reopened
                .search("legacyword", None, 0, 10)
                .unwrap()
                .hits
                .len(),
            1
        );
        reopened
            .reindex_with(vec![
                row("b", "新模板", &[], "", "freshword"),
                row("c", "另一个", &[], "", "otherword"),
            ])
            .unwrap();
        assert_eq!(reopened.doc_count(), 2);
        assert!(reopened
            .search("legacyword", None, 0, 10)
            .unwrap()
            .hits
            .is_empty());
        assert_eq!(
            reopened
                .search("freshword", None, 0, 10)
                .unwrap()
                .hits
                .len(),
            1
        );
    }
}
