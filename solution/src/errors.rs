// определяем пользовательские ошибки для нашего сервиса

use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use std::fmt;

// перечисление для различных типов ошибок
#[derive(Debug, Clone)]
pub enum ServiceError {
    InternalServerError(String),
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    ValidationFailed(Vec<ValidationErrorField>),
    Locked(String),
    DatabaseError(String),
}

// модель ошибки валидации поля
#[derive(Debug, Clone, Serialize)]
pub struct ValidationErrorField {
    pub field: String,
    pub message: String,
    pub value: Option<String>,
}

// реализация Display для ServiceError
impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ServiceError::InternalServerError(msg) => write!(f, "Internal Server Error: {}", msg),
            ServiceError::BadRequest(msg) => write!(f, "Bad Request: {}", msg),
            ServiceError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            ServiceError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            ServiceError::NotFound(msg) => write!(f, "Not Found: {}", msg),
            ServiceError::Conflict(msg) => write!(f, "Conflict: {}", msg),
            ServiceError::ValidationFailed(errors) => write!(f, "Validation Failed: {:?}", errors),
            ServiceError::Locked(msg) => write!(f, "Locked: {}", msg),
            ServiceError::DatabaseError(msg) => write!(f, "Database Error: {}", msg),
        }
    }
}

// реализация ResponseError для ServiceError
impl ResponseError for ServiceError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ServiceError::InternalServerError(msg) => {
                HttpResponse::InternalServerError().json(ApiErrorResponse {
                    code: "INTERNAL_ERROR".to_string(),
                    message: msg.clone(),
                    timestamp: chrono::Utc::now(),
                    path: "".to_string(), // будет заполнено middleware
                    trace_id: uuid::Uuid::new_v4().to_string(),
                    details: None,
                })
            },
            ServiceError::BadRequest(msg) => {
                HttpResponse::BadRequest().json(ApiErrorResponse {
                    code: "BAD_REQUEST".to_string(),
                    message: msg.clone(),
                    timestamp: chrono::Utc::now(),
                    path: "".to_string(),
                    trace_id: uuid::Uuid::new_v4().to_string(),
                    details: None,
                })
            },
            ServiceError::Unauthorized(msg) => {
                HttpResponse::Unauthorized().json(ApiErrorResponse {
                    code: "UNAUTHORIZED".to_string(),
                    message: msg.clone(),
                    timestamp: chrono::Utc::now(),
                    path: "".to_string(),
                    trace_id: uuid::Uuid::new_v4().to_string(),
                    details: None,
                })
            },
            ServiceError::Forbidden(msg) => {
                HttpResponse::Forbidden().json(ApiErrorResponse {
                    code: "FORBIDDEN".to_string(),
                    message: msg.clone(),
                    timestamp: chrono::Utc::now(),
                    path: "".to_string(),
                    trace_id: uuid::Uuid::new_v4().to_string(),
                    details: None,
                })
            },
            ServiceError::NotFound(msg) => {
                HttpResponse::NotFound().json(ApiErrorResponse {
                    code: "NOT_FOUND".to_string(),
                    message: msg.clone(),
                    timestamp: chrono::Utc::now(),
                    path: "".to_string(),
                    trace_id: uuid::Uuid::new_v4().to_string(),
                    details: None,
                })
            },
            ServiceError::Conflict(msg) => {
                HttpResponse::Conflict().json(ApiErrorResponse {
                    code: "CONFLICT".to_string(),
                    message: msg.clone(),
                    timestamp: chrono::Utc::now(),
                    path: "".to_string(),
                    trace_id: uuid::Uuid::new_v4().to_string(),
                    details: None,
                })
            },
            ServiceError::ValidationFailed(errors) => {
                HttpResponse::UnprocessableEntity().json(ApiErrorResponse {
                    code: "VALIDATION_FAILED".to_string(),
                    message: "Validation failed".to_string(),
                    timestamp: chrono::Utc::now(),
                    path: "".to_string(),
                    trace_id: uuid::Uuid::new_v4().to_string(),
                    details: Some(serde_json::json!(errors)),
                })
            },
            ServiceError::Locked(msg) => {
                HttpResponse::Locked().json(ApiErrorResponse {
                    code: "USER_INACTIVE".to_string(),
                    message: msg.clone(),
                    timestamp: chrono::Utc::now(),
                    path: "".to_string(),
                    trace_id: uuid::Uuid::new_v4().to_string(),
                    details: None,
                })
            },
            ServiceError::DatabaseError(msg) => {
                HttpResponse::InternalServerError().json(ApiErrorResponse {
                    code: "DATABASE_ERROR".to_string(),
                    message: msg.clone(),
                    timestamp: chrono::Utc::now(),
                    path: "".to_string(),
                    trace_id: uuid::Uuid::new_v4().to_string(),
                    details: None,
                })
            },
        }
    }
}

// модель ответа ошибки api
#[derive(Debug, Serialize)]
pub struct ApiErrorResponse {
    pub code: String,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub path: String,
    pub trace_id: String,
    pub details: Option<serde_json::Value>,
}

// реализация From для преобразования стандартных ошибок
impl From<std::io::Error> for ServiceError {
    fn from(error: std::io::Error) -> Self {
        ServiceError::InternalServerError(error.to_string())
    }
}

impl From<serde_json::Error> for ServiceError {
    fn from(error: serde_json::Error) -> Self {
        ServiceError::BadRequest(error.to_string())
    }
}

impl From<sqlx::Error> for ServiceError {
    fn from(error: sqlx::Error) -> Self {
        ServiceError::DatabaseError(error.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for ServiceError {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        ServiceError::Unauthorized(error.to_string())
    }
}

impl From<bcrypt::BcryptError> for ServiceError {
    fn from(error: bcrypt::BcryptError) -> Self {
        ServiceError::InternalServerError(error.to_string())
    }
}