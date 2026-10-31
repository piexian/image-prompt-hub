//! 数据模型：数据库行结构与对外 JSON 结构。目录快照按 TemplateJson 的字段顺序序列化。

use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TemplateRow {
    pub id: String,
    pub name: String,
    pub ai_description: String,
    pub content: String,
    pub defaults: serde_json::Value,
    pub reference: String,
    pub tags: Vec<String>,
    pub author: Option<String>,
    pub source_url: Option<String>,
    pub owner_key_id: Uuid,
    pub owner_email_hmac: String,
    pub status: String,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 对外模板对象；字段顺序固定，序列化结果参与目录哈希。
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TemplateJson {
    pub id: String,
    pub name: String,
    pub ai_description: String,
    pub content: String,
    #[schema(value_type = Object)]
    pub defaults: serde_json::Value,
    pub reference: String,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// 出处或许可页面的 https 链接；未提供时响应里不出现这个键。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    pub version: i64,
    #[schema(value_type = String)]
    pub created_at: DateTime<Utc>,
    #[schema(value_type = String)]
    pub updated_at: DateTime<Utc>,
}

impl From<TemplateRow> for TemplateJson {
    fn from(row: TemplateRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            ai_description: row.ai_description,
            content: row.content,
            defaults: row.defaults,
            reference: row.reference,
            tags: row.tags,
            author: row.author,
            source_url: row.source_url,
            version: row.version,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// `GET /v1/me/templates` 的条目：在公开结构上补 status。
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OwnedTemplateJson {
    #[serde(flatten)]
    pub template: TemplateJson,
    pub status: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ApiKeyRow {
    pub id: Uuid,
    pub key_prefix: String,
    pub key_hash: String,
    pub email_hmac: String,
    pub scopes: Vec<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// 导出 / 导入 / 目录快照共用的 JSON 包格式。
#[derive(Debug, Clone, Serialize)]
pub struct TemplatePackage {
    pub format: String,
    pub version: u32,
    pub updated_at: String,
    pub templates: Vec<TemplateJson>,
}

pub const PACKAGE_FORMAT: &str = "gemini-image-templates";
pub const PACKAGE_VERSION: u32 = 1;
