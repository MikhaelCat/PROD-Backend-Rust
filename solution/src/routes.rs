// импортируем необходимые зависимости
use actix_web::{web, HttpRequest, HttpResponse, Result};

use crate::models::*;
use crate::services::*;
use crate::errors::ServiceError;
use crate::validation;
use sqlx::PgPool;
use uuid::Uuid;

// функция для извлечения JWT токена из заголовка
fn extract_jwt_from_header(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|auth_header| {
            if auth_header.starts_with("Bearer ") {
                Some(auth_header[7..].to_string())
            } else {
                None
            }
        })
}

// функция для проверки роли пользователя
fn check_user_role(req: &HttpRequest, required_roles: &[UserRole]) -> Result<(Uuid, UserRole), ServiceError> {
    if let Some(token) = extract_jwt_from_header(req) {
        match crate::services::validate_jwt_token(&token) {
            Ok(claims) => {
                let user_id = Uuid::parse_str(&claims.sub)
                    .map_err(|_| ServiceError::Unauthorized("Invalid token".to_string()))?;
                
                let user_role = match claims.role.as_str() {
                    "ADMIN" => UserRole::Admin,
                    "USER" => UserRole::User,
                    _ => return Err(ServiceError::Unauthorized("Invalid role in token".to_string())),
                };
                
                // проверяем, есть ли у пользователя необходимая роль
                if required_roles.contains(&user_role) {
                    Ok((user_id, user_role))
                } else {
                    Err(ServiceError::Forbidden("Insufficient permissions".to_string()))
                }
            }
            Err(_) => Err(ServiceError::Unauthorized("Invalid or expired token".to_string())),
        }
    } else {
        Err(ServiceError::Unauthorized("Authorization header missing".to_string()))
    }
}

// функция для настройки маршрутов сервиса
pub fn config_services(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .service(ping_handler)
            .service(register_handler)
            .service(login_handler)
            .service(get_current_user)
            .service(update_current_user)
            .service(get_user_by_id)
            .service(update_user_by_id)
            .service(delete_user_by_id)
            .service(get_users_list)
            .service(create_user_admin)
            .service(create_fraud_rule)
            .service(get_fraud_rules)
            .service(get_fraud_rule_by_id)
            .service(update_fraud_rule_by_id)
            .service(delete_fraud_rule_by_id)
            .service(validate_fraud_rule)
            .service(create_transaction)
            .service(get_transactions)
            .service(get_transaction_by_id)
            .service(create_transactions_batch)
    );
}

// handler для проверки работоспособности сервиса
#[actix_web::get("/ping")]
async fn ping_handler() -> impl actix_web::Responder {
    actix_web::HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}

// обработчик регистрации
#[actix_web::post("/auth/register")]
async fn register_handler(
    body: web::Json<RegisterRequest>,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let request = body.into_inner();
    let response = AuthService::register_user(&db_pool, request).await?;
    Ok(HttpResponse::Created().json(response))
}

// обработчик входа
#[actix_web::post("/auth/login")]
async fn login_handler(
    body: web::Json<LoginRequest>,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let request = body.into_inner();
    let response = AuthService::authenticate_user(&db_pool, request).await?;
    Ok(HttpResponse::Ok().json(response))
}

// обработчик получения текущего пользователя
#[actix_web::get("/users/me")]
async fn get_current_user(
    req: HttpRequest,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let (user_id, _) = check_user_role(&req, &[UserRole::User, UserRole::Admin])?;
    let user = UserService::get_current_user(user_id, &db_pool).await?;
    Ok(HttpResponse::Ok().json(user))
}

// обработчик обновления текущего пользователя
#[actix_web::put("/users/me")]
async fn update_current_user(
    req: HttpRequest,
    body: web::Json<UserUpdateRequest>,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let (user_id, _) = check_user_role(&req, &[UserRole::User, UserRole::Admin])?;
    let request = body.into_inner();
    let user = UserService::update_current_user(user_id, request, &db_pool).await?;
    Ok(HttpResponse::Ok().json(user))
}

// обработчик получения пользователя по id
#[actix_web::get("/users/{id}")]
async fn get_user_by_id(
    path: web::Path<String>,
    req: HttpRequest,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let user_id = Uuid::parse_str(&path).map_err(|_| ServiceError::BadRequest("Invalid user ID".to_string()))?;
    let (current_user_id, current_user_role) = check_user_role(&req, &[UserRole::User, UserRole::Admin])?;
    let user = UserService::get_user_by_id(user_id, current_user_id, &current_user_role, &db_pool).await?;
    Ok(HttpResponse::Ok().json(user))
}

// обработчик обновления пользователя по id
#[actix_web::put("/users/{id}")]
async fn update_user_by_id(
    path: web::Path<String>,
    req: HttpRequest,
    body: web::Json<UserUpdateRequest>,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let target_user_id = Uuid::parse_str(&path).map_err(|_| ServiceError::BadRequest("Invalid user ID".to_string()))?;
    let (current_user_id, current_user_role) = check_user_role(&req, &[UserRole::User, UserRole::Admin])?;
    let request = body.into_inner();
    let user = UserService::update_user_by_id(target_user_id, request, current_user_id, &current_user_role, &db_pool).await?;
    Ok(HttpResponse::Ok().json(user))
}

// обработчик удаления (деактивации) пользователя
#[actix_web::delete("/users/{id}")]
async fn delete_user_by_id(
    path: web::Path<String>,
    req: HttpRequest,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let target_user_id = Uuid::parse_str(&path).map_err(|_| ServiceError::BadRequest("Invalid user ID".to_string()))?;
    let (current_user_id, current_user_role) = check_user_role(&req, &[UserRole::Admin])?;
    let success = UserService::deactivate_user(target_user_id, current_user_id, &current_user_role, &db_pool).await?;
    if success {
        Ok(HttpResponse::NoContent().finish())
    } else {
        Err(ServiceError::NotFound("User not found".to_string()))
    }
}

// обработчик получения списка пользователей
#[actix_web::get("/users")]
async fn get_users_list(
    query: web::Query<std::collections::HashMap<String, String>>,
    req: HttpRequest,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let (_, current_user_role) = check_user_role(&req, &[UserRole::Admin])?;
    let page = query.get("page").and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    let size = query.get("size").and_then(|s| s.parse::<i64>().ok()).unwrap_or(20);
    let users = UserService::get_all_users(&current_user_role, page, size, &db_pool).await?;
    Ok(HttpResponse::Ok().json(users))
}

// обработчик создания пользователя администратором
#[actix_web::post("/users")]
async fn create_user_admin(
    body: web::Json<UserCreateRequest>,
    req: HttpRequest,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let (_, _current_user_role) = check_user_role(&req, &[UserRole::Admin])?;
    let request = body.into_inner();
    
    // валидируем email
    validation::validate_email(&request.email).map_err(ServiceError::ValidationFailed)?;
    
    // валидируем пароль
    validation::validate_password(&request.password).map_err(ServiceError::ValidationFailed)?;
    
    // валидируем полное имя
    validation::validate_full_name(&request.full_name).map_err(ServiceError::ValidationFailed)?;
    
    // валидируем возраст
    validation::validate_age(request.age).map_err(ServiceError::ValidationFailed)?;
    
    // валидируем регион
    validation::validate_region(request.region.clone()).map_err(ServiceError::ValidationFailed)?;
    
    // проверяем, существует ли пользователь с таким email
    if let Some(_) = User::find_by_email(&db_pool, &request.email).await.map_err(ServiceError::from)? {
        return Err(ServiceError::Conflict("Email already exists".to_string()));
    }
    
    // хешируем пароль
    let hashed_password = bcrypt::hash(request.password, bcrypt::DEFAULT_COST).map_err(ServiceError::from)?;
    
    // создаем нового пользователя
    let now = chrono::Utc::now();
    let user = User {
        id: Uuid::new_v4(),
        email: request.email,
        full_name: request.full_name,
        age: request.age,
        region: request.region,
        gender: request.gender,
        marital_status: request.marital_status,
        role: request.role, // используем роль из запроса
        is_active: true,
        password_hash: hashed_password,
        created_at: now,
        updated_at: now,
    };
    
    let saved_user = User::create(&db_pool, &user).await.map_err(ServiceError::from)?;
    Ok(HttpResponse::Created().json(saved_user))
}

// обработчик создания правила
#[actix_web::post("/fraud-rules")]
async fn create_fraud_rule(
    body: web::Json<FraudRuleCreateRequest>,
    req: HttpRequest,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let (_, current_user_role) = check_user_role(&req, &[UserRole::Admin])?;
    let request = body.into_inner();
    let rule = FraudRuleService::create_fraud_rule(request, &current_user_role, &db_pool).await?;
    Ok(HttpResponse::Created().json(rule))
}

// обработчик получения списка правил
#[actix_web::get("/fraud-rules")]
async fn get_fraud_rules(
    req: HttpRequest,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let (_, current_user_role) = check_user_role(&req, &[UserRole::Admin])?;
    let rules = FraudRuleService::get_all_fraud_rules(&current_user_role, &db_pool).await?;
    Ok(HttpResponse::Ok().json(rules))
}

// обработчик получения правила по id
#[actix_web::get("/fraud-rules/{id}")]
async fn get_fraud_rule_by_id(
    path: web::Path<String>,
    req: HttpRequest,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let rule_id = Uuid::parse_str(&path).map_err(|_| ServiceError::BadRequest("Invalid rule ID".to_string()))?;
    let (_, current_user_role) = check_user_role(&req, &[UserRole::Admin])?;
    let rule = FraudRuleService::get_fraud_rule_by_id(rule_id, &current_user_role, &db_pool).await?;
    Ok(HttpResponse::Ok().json(rule))
}

// обработчик обновления правила
#[actix_web::put("/fraud-rules/{id}")]
async fn update_fraud_rule_by_id(
    path: web::Path<String>,
    body: web::Json<FraudRuleUpdateRequest>,
    req: HttpRequest,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let rule_id = Uuid::parse_str(&path).map_err(|_| ServiceError::BadRequest("Invalid rule ID".to_string()))?;
    let (_, current_user_role) = check_user_role(&req, &[UserRole::Admin])?;
    let request = body.into_inner();
    let rule = FraudRuleService::update_fraud_rule_by_id(rule_id, request, &current_user_role, &db_pool).await?;
    Ok(HttpResponse::Ok().json(rule))
}

// обработчик удаления (деактивации) правила
#[actix_web::delete("/fraud-rules/{id}")]
async fn delete_fraud_rule_by_id(
    path: web::Path<String>,
    req: HttpRequest,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let rule_id = Uuid::parse_str(&path).map_err(|_| ServiceError::BadRequest("Invalid rule ID".to_string()))?;
    let (_, current_user_role) = check_user_role(&req, &[UserRole::Admin])?;
    let success = FraudRuleService::deactivate_fraud_rule(rule_id, &current_user_role, &db_pool).await?;
    if success {
        Ok(HttpResponse::NoContent().finish())
    } else {
        Err(ServiceError::NotFound("Fraud rule not found".to_string()))
    }
}

// обработчик валидации правила
#[actix_web::post("/fraud-rules/validate")]
async fn validate_fraud_rule(
    body: web::Json<FraudRuleValidateRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, ServiceError> {
    let (_, _current_user_role) = check_user_role(&req, &[UserRole::Admin])?;
    let request = body.into_inner();
    let result = FraudRuleService::validate_fraud_rule(request).await?;
    Ok(HttpResponse::Ok().json(result))
}

// обработчик создания транзакции
#[actix_web::post("/transactions")]
async fn create_transaction(
    body: web::Json<TransactionCreateRequest>,
    req: HttpRequest,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let (current_user_id, current_user_role) = check_user_role(&req, &[UserRole::User, UserRole::Admin])?;
    let request = body.into_inner();
    let response = TransactionService::create_transaction(request, Some(current_user_id), &current_user_role, &db_pool).await?;
    Ok(HttpResponse::Created().json(response))
}

// обработчик получения списка транзакций
#[actix_web::get("/transactions")]
async fn get_transactions(
    _query: web::Query<std::collections::HashMap<String, String>>,
    req: HttpRequest,
    _db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    // TODO: реализовать получение списка транзакций
    let (_, _current_user_role) = check_user_role(&req, &[UserRole::User, UserRole::Admin])?;
    // Пока возвращаем пустой список
    Ok(HttpResponse::Ok().json(PagedTransactions { items: vec![], total: 0, page: 0, size: 20 }))
}

// обработчик получения транзакции по id
#[actix_web::get("/transactions/{id}")]
async fn get_transaction_by_id(
    path: web::Path<String>,
    req: HttpRequest,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let transaction_id = Uuid::parse_str(&path).map_err(|_| ServiceError::BadRequest("Invalid transaction ID".to_string()))?;
    let (current_user_id, current_user_role) = check_user_role(&req, &[UserRole::User, UserRole::Admin])?;
    
    let transaction = Transaction::find_by_id(&db_pool, transaction_id)
        .await
        .map_err(ServiceError::from)?
        .ok_or_else(|| ServiceError::NotFound("Transaction not found".to_string()))?;
    
    // проверяем права доступа
    if current_user_role != UserRole::Admin && transaction.user_id != current_user_id {
        return Err(ServiceError::Forbidden("Access denied".to_string()));
    }
    
    // TODO: нужно также получить результаты правил для этой транзакции
    // Пока возвращаем заглушку
    let response = TransactionCreateResponse {
        transaction,
        rule_results: vec![], // в реальной реализации нужно получить результаты правил
    };
    
    Ok(HttpResponse::Ok().json(response))
}

// обработчик создания пакета транзакций
#[actix_web::post("/transactions/batch")]
async fn create_transactions_batch(
    body: web::Json<TransactionBatchRequest>,
    req: HttpRequest,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, ServiceError> {
    let (current_user_id, current_user_role) = check_user_role(&req, &[UserRole::User, UserRole::Admin])?;
    let request = body.into_inner();
    
    let mut items = Vec::new();
    
    for (index, transaction_request) in request.items.into_iter().enumerate() {
        match TransactionService::create_transaction(transaction_request, Some(current_user_id), &current_user_role, &db_pool).await {
            Ok(response) => {
                items.push(TransactionBatchItem {
                    index,
                    decision: Some(response),
                    error: None,
                });
            }
            Err(error) => {
                items.push(TransactionBatchItem {
                    index,
                    decision: None,
                    error: Some(BatchTransactionError {
                        code: match &error {
                            ServiceError::BadRequest(_) => "BAD_REQUEST".to_string(),
                            ServiceError::Unauthorized(_) => "UNAUTHORIZED".to_string(),
                            ServiceError::Forbidden(_) => "FORBIDDEN".to_string(),
                            ServiceError::NotFound(_) => "NOT_FOUND".to_string(),
                            ServiceError::Conflict(_) => "CONFLICT".to_string(),
                            ServiceError::ValidationFailed(_) => "VALIDATION_FAILED".to_string(),
                            ServiceError::Locked(_) => "USER_INACTIVE".to_string(),
                            ServiceError::DatabaseError(_) => "INTERNAL_ERROR".to_string(),
                            ServiceError::InternalServerError(_) => "INTERNAL_ERROR".to_string(),
                        },
                        message: format!("{}", error),
                    }),
                });
            }
        }
    }
    
    let response = TransactionBatchResponse { items };
    
    // Проверяем, есть ли ошибки
    let has_errors = response.items.iter().any(|item| item.error.is_some());
    
    if has_errors {
        Ok(HttpResponse::PartialContent().json(response)) // 207 Partial Content
    } else {
        Ok(HttpResponse::Created().json(response)) // 201 Created
    }
}