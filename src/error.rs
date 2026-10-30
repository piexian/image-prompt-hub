//! 统一 API 错误：JSON `{"error": {"code", "message"}}`。

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    PayloadTooLarge,
    EmailNotAllowed,
    VerificationInvalid,
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited => "rate_limited",
            Self::PayloadTooLarge => "payload_too_large",
            Self::EmailNotAllowed => "email_not_allowed",
            Self::VerificationInvalid => "verification_invalid",
            Self::Internal => "internal",
        }
    }

    pub fn status(self) -> StatusCode {
        match self {
            Self::BadRequest | Self::EmailNotAllowed => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::VerificationInvalid => StatusCode::BAD_REQUEST,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    pub retry_after: Option<u64>,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retry_after: None,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::BadRequest, message)
    }

    pub fn unauthorized() -> Self {
        Self::new(ErrorCode::Unauthorized, "缺少或无效的 API 密钥")
    }

    pub fn forbidden() -> Self {
        Self::new(ErrorCode::Forbidden, "没有权限执行此操作")
    }

    pub fn not_found() -> Self {
        Self::new(ErrorCode::NotFound, "资源不存在")
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, message)
    }

    pub fn rate_limited(retry_after_secs: u64) -> Self {
        Self {
            code: ErrorCode::RateLimited,
            message: "请求过于频繁，请稍后再试".into(),
            retry_after: Some(retry_after_secs.max(1)),
        }
    }

    pub fn payload_too_large() -> Self {
        Self::new(ErrorCode::PayloadTooLarge, "请求体过大")
    }

    pub fn internal() -> Self {
        Self::new(ErrorCode::Internal, "服务器内部错误")
    }

    /// 记录底层错误后返回统一的 internal，避免细节外泄。
    pub fn internal_with(error: impl std::fmt::Display) -> Self {
        tracing::error!(error = %error, "内部错误");
        Self::internal()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({
            "error": {"code": self.code.as_str(), "message": self.message}
        });
        let mut response = (self.code.status(), Json(body)).into_response();
        if let Some(secs) = self.retry_after {
            if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

/// PostgreSQL 拒绝存储的字符（NUL 等，SQLSTATE 22021 / 22P05）来自请求里的参数，
/// 属于调用方错误，不能当成 500。
const INVALID_CHARACTER_SQLSTATES: [&str; 2] = ["22021", "22P05"];

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db_error) = &error {
            if db_error
                .code()
                .is_some_and(|code| INVALID_CHARACTER_SQLSTATES.contains(&code.as_ref()))
            {
                return ApiError::bad_request("请求里包含无法存储的字符（例如 NUL）");
            }
        }
        ApiError::internal_with(error)
    }
}
