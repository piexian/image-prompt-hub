//! OpenAPI 文档与 llms.txt。

use axum::extract::State;
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use utoipa::OpenApi;

use crate::api::{admin, keys, public, write};
use crate::catalog::CatalogMeta;
use crate::models::{OwnedTemplateJson, TemplateJson};
use crate::state::AppState;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "image-prompt-hub",
        version = env!("CARGO_PKG_VERSION"),
        description = "AstrBot 图片生成插件的在线提示词模板服务：公开只读检索与下载，申请密钥后可写。"
    ),
    paths(
        public::list_templates,
        public::batch_templates,
        public::get_template,
        public::list_tags,
        public::status,
        public::catalog_version,
        public::catalog,
        public::report_template,
        keys::request_key,
        keys::verify_page,
        keys::verify_confirm,
        keys::key_info,
        keys::revoke_own_key,
        write::create_template,
        write::import_templates,
        write::update_template,
        write::delete_template,
        write::my_templates,
        admin::list_reports,
        admin::hide_template,
        admin::restore_template,
        admin::lookup_keys_by_email,
        admin::ban_account,
        admin::unban_account,
        admin::revoke_key,
    ),
    components(
        schemas(
            TemplateJson,
            OwnedTemplateJson,
            CatalogMeta,
            public::ListEntry,
            public::ListResponse,
            public::BatchResponse,
            public::TagCount,
            public::TagsResponse,
            public::StatusResponse,
            public::ReportBody,
            keys::KeyRequestBody,
            keys::RequestKeyResponse,
            keys::KeyInfo,
            keys::RevokeResponse,
            write::TemplateUpsertDoc,
            write::ImportResultItem,
            write::ImportResponse,
            write::MyTemplatesResponse,
            admin::ReportEntry,
            admin::ReportsResponse,
            admin::StatusChangeResponse,
            admin::AdminKeyEntry,
            admin::AdminKeysResponse,
            admin::AdminKeysLookupBody,
            admin::BanBody,
            admin::BanResponse,
            admin::UnbanBody,
            admin::UnbanResponse,
        )
    ),
    tags(
        (name = "templates", description = "公开只读的模板接口"),
        (name = "catalog", description = "目录快照（插件本地缓存同步用）"),
        (name = "keys", description = "密钥申请、验证与自助吊销"),
        (name = "write", description = "需要 write 权限的写接口"),
        (name = "admin", description = "需要 admin 权限的管理接口"),
        (name = "meta", description = "服务状态"),
    )
)]
struct ApiDoc;

pub async fn openapi_json() -> Response {
    let json = ApiDoc::openapi()
        .to_pretty_json()
        .expect("OpenAPI 序列化不会失败");
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        json,
    )
        .into_response()
}

const LLMS_TXT: &str = include_str!("../llms.txt");

pub async fn llms_txt(State(state): State<AppState>) -> Response {
    let body = LLMS_TXT.replace("{BASE_URL}", &state.config.public_base_url);
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}
