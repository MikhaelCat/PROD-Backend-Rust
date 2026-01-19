// определяем модели данных для нашей системы антифрода

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

// модель пользователя
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub full_name: String,
    pub age: Option<i32>,
    pub region: Option<String>,
    pub gender: Option<UserGender>,
    pub marital_status: Option<UserMaritalStatus>,
    pub role: UserRole,
    pub is_active: bool,
    pub password_hash: String,  // хеш пароля
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// перечисление для пола пользователя
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserGender {
    #[serde(rename = "MALE")]
    Male,
    #[serde(rename = "FEMALE")]
    Female,
}

// перечисление для семейного положения пользователя
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserMaritalStatus {
    #[serde(rename = "SINGLE")]
    Single,
    #[serde(rename = "MARRIED")]
    Married,
    #[serde(rename = "DIVORCED")]
    Divorced,
    #[serde(rename = "WIDOWED")]
    Widowed,
}

// перечисление для роли пользователя
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserRole {
    #[serde(rename = "USER")]
    User,
    #[serde(rename = "ADMIN")]
    Admin,
}

// модель запроса регистрации
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub full_name: String,
    pub age: Option<i32>,
    pub region: Option<String>,
    pub gender: Option<UserGender>,
    pub marital_status: Option<UserMaritalStatus>,
}

// модель ответа аутентификации
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub user: User,
}

// модель запроса входа
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

// модель обновления пользователя
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserUpdateRequest {
    pub full_name: String,
    pub age: Option<i32>,
    pub region: Option<String>,
    pub gender: Option<UserGender>,
    pub marital_status: Option<UserMaritalStatus>,
    pub role: Option<UserRole>,      // доступно только администратору
    pub is_active: Option<bool>,    // доступно только администратору
}

// модель создания пользователя администратором
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCreateRequest {
    pub email: String,
    pub password: String,
    pub full_name: String,
    pub age: Option<i32>,
    pub region: Option<String>,
    pub gender: Option<UserGender>,
    pub marital_status: Option<UserMaritalStatus>,
    pub role: UserRole,  // обязательное поле для администратора
}

// модель страницы пользователей
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagedUsers {
    pub items: Vec<User>,
    pub total: i64,
    pub page: i64,
    pub size: i64,
}

// модель правила антифрода
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudRule {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub dsl_expression: String,
    pub enabled: bool,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// модель создания правила антифрода
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudRuleCreateRequest {
    pub name: String,
    pub description: Option<String>,
    pub dsl_expression: String,
    pub enabled: bool,
    pub priority: i32,
}

// модель обновления правила антифрода
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudRuleUpdateRequest {
    pub name: String,
    pub description: Option<String>,
    pub dsl_expression: String,
    pub enabled: bool,
    pub priority: i32,
}

// модель валидации правила
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudRuleValidateRequest {
    pub dsl_expression: String,
}

// модель результата валидации
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudRuleValidateResponse {
    pub is_valid: bool,
    pub normalized_expression: Option<String>,
    pub errors: Vec<FraudRuleValidationError>,
}

// модель ошибки валидации правила
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudRuleValidationError {
    pub code: String,
    pub message: String,
    pub position: Option<usize>,
    pub near: Option<String>,
}

// модель транзакции
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: Uuid,
    pub user_id: Uuid,
    pub amount: f64,
    pub currency: String,
    pub status: TransactionStatus,
    pub merchant_id: Option<String>,
    pub merchant_category_code: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub device_id: Option<String>,
    pub channel: Option<TransactionChannel>,
    pub location: Option<TransactionLocation>,
    pub is_fraud: bool,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub created_at: DateTime<Utc>,
}

// перечисление статуса транзакции
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionStatus {
    #[serde(rename = "APPROVED")]
    Approved,
    #[serde(rename = "DECLINED")]
    Declined,
}

// перечисление канала транзакции
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionChannel {
    #[serde(rename = "WEB")]
    Web,
    #[serde(rename = "MOBILE")]
    Mobile,
    #[serde(rename = "POS")]
    Pos,
    #[serde(rename = "OTHER")]
    Other,
}

// модель местоположения транзакции
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionLocation {
    pub country: String,
    pub city: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

// модель создания транзакции
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionCreateRequest {
    pub user_id: Option<Uuid>,  // для администратора, пользователь игнорируется для обычного пользователя
    pub amount: f64,
    pub currency: String,
    pub merchant_id: Option<String>,
    pub merchant_category_code: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub device_id: Option<String>,
    pub channel: Option<TransactionChannel>,
    pub location: Option<TransactionLocation>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

// модель результата проверки правила
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResult {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub priority: i32,
    pub enabled: bool,
    pub matched: bool,
    pub description: String,
}

// модель ответа создания транзакции
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionCreateResponse {
    pub transaction: Transaction,
    pub rule_results: Vec<RuleResult>,
}

// модель пакетной транзакции
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionBatchRequest {
    pub items: Vec<TransactionCreateRequest>,
}

// модель элемента пакетной транзакции
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionBatchItem {
    pub index: usize,
    pub decision: Option<TransactionCreateResponse>,
    pub error: Option<BatchTransactionError>,
}

// модель ошибки пакетной транзакции
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTransactionError {
    pub code: String,
    pub message: String,
}

// модель ответа пакетной транзакции
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionBatchResponse {
    pub items: Vec<TransactionBatchItem>,
}

// модель контекста оценки правила
#[derive(Debug, Clone)]
pub struct RuleEvaluationContext<'a> {
    pub transaction: &'a Transaction,
    pub user: &'a User,
    pub metadata: &'a Option<HashMap<String, serde_json::Value>>,
    pub timestamp: DateTime<Utc>,
}