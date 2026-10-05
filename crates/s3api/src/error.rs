//! S3 errors and their XML responses.

use axum::body::Body;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use engine::EngineError;
use tracing::warn;

/// An S3 error: the code clients match on, the HTTP status, and a message.
#[derive(Debug, thiserror::Error)]
#[error("{code}: {message}")]
pub struct S3Error {
    pub code: &'static str,
    pub status: StatusCode,
    pub message: String,
}

impl S3Error {
    pub fn new(code: &'static str, status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            code,
            status,
            message: message.into(),
        }
    }

    pub fn access_denied(message: impl Into<String>) -> Self {
        Self::new("AccessDenied", StatusCode::FORBIDDEN, message)
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new("InvalidArgument", StatusCode::BAD_REQUEST, message)
    }

    pub fn malformed_xml() -> Self {
        Self::new(
            "MalformedXML",
            StatusCode::BAD_REQUEST,
            "the XML body is not well formed",
        )
    }

    pub fn not_implemented(message: impl Into<String>) -> Self {
        Self::new("NotImplemented", StatusCode::NOT_IMPLEMENTED, message)
    }

    pub fn no_such_upload(upload_id: &str) -> Self {
        Self::new(
            "NoSuchUpload",
            StatusCode::NOT_FOUND,
            format!("no such upload: {upload_id}"),
        )
    }

    pub fn precondition_failed() -> Self {
        Self::new(
            "PreconditionFailed",
            StatusCode::PRECONDITION_FAILED,
            "a precondition does not hold",
        )
    }

    pub fn invalid_range(message: impl Into<String>) -> Self {
        Self::new("InvalidRange", StatusCode::RANGE_NOT_SATISFIABLE, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("InternalError", StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl From<EngineError> for S3Error {
    fn from(e: EngineError) -> Self {
        let message = e.to_string();
        let (code, status) = match e {
            EngineError::NoSuchBucket(_) => ("NoSuchBucket", StatusCode::NOT_FOUND),
            EngineError::NoSuchKey { .. } => ("NoSuchKey", StatusCode::NOT_FOUND),
            EngineError::BucketAlreadyExists(_) => {
                ("BucketAlreadyOwnedByYou", StatusCode::CONFLICT)
            }
            EngineError::BucketNotEmpty(_) => ("BucketNotEmpty", StatusCode::CONFLICT),
            EngineError::InvalidBucketName(_) => ("InvalidBucketName", StatusCode::BAD_REQUEST),
            EngineError::InvalidKey(_) => ("KeyTooLongError", StatusCode::BAD_REQUEST),
            EngineError::PreconditionFailed { .. } => {
                ("PreconditionFailed", StatusCode::PRECONDITION_FAILED)
            }
            EngineError::InvalidRange { .. } => ("InvalidRange", StatusCode::RANGE_NOT_SATISFIABLE),
            // The buffer drains when the remote comes back: clients back off and retry.
            EngineError::BufferFull { .. } => ("SlowDown", StatusCode::SERVICE_UNAVAILABLE),
            _ => {
                warn!(%message, "internal error");
                ("InternalError", StatusCode::INTERNAL_SERVER_ERROR)
            }
        };

        Self {
            code,
            status,
            message,
        }
    }
}

impl IntoResponse for S3Error {
    fn into_response(self) -> axum::response::Response {
        let body = crate::xml::error(self.code, &self.message);

        Response::builder()
            .status(self.status)
            .header("content-type", "application/xml")
            .body(Body::from(body))
            .expect("static headers are valid")
    }
}
