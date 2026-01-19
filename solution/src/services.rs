// модуль для бизнес-логики сервиса

use crate::models::*;
use crate::errors::ServiceError;
use crate::validation;
use crate::database;
use crate::dsl;
use sqlx::PgPool;
use uuid::Uuid;
use chrono::Utc;
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, decode, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;

// секретный ключ для jwt
const JWT_SECRET_KEY: &str = "RANDOM_SECRET";

// структура для jwt токена
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,        // user id
    pub role: String,       // user role
    pub exp: usize,         // expiration time
    pub iat: usize,         // issued at time
}

// сервис аутентификации
pub struct AuthService;

impl AuthService {
    // регистрация нового пользователя
    pub async fn register_user(pool: &PgPool, request: RegisterRequest) -> Result<AuthResponse, ServiceError> {
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
        if let Some(_) = User::find_by_email(pool, &request.email).await.map_err(ServiceError::DatabaseError)? {
            return Err(ServiceError::Conflict("Email already exists".to_string()));
        }
        
        // хешируем пароль
        let hashed_password = hash(request.password, DEFAULT_COST).map_err(ServiceError::InternalServerError)?;
        
        // создаем нового пользователя
        let now = Utc::now();
        let user = User {
            id: Uuid::new_v4(),
            email: request.email,
            full_name: request.full_name,
            age: request.age,
            region: request.region,
            gender: request.gender,
            marital_status: request.marital_status,
            role: UserRole::User, // по умолчанию пользователь
            is_active: true,
            created_at: now,
            updated_at: now,
        };
        
        // сохраняем пользователя в базе данных
        let saved_user = User::create(pool, &user).await.map_err(ServiceError::DatabaseError)?;
        
        // генерируем jwt токен
        let token = generate_jwt_token(&saved_user.id.to_string(), &saved_user.role)?;
        
        Ok(AuthResponse {
            access_token: token,
            expires_in: 3600, // 1 час
            user: saved_user,
        })
    }
    
    // аутентификация пользователя
    pub async fn authenticate_user(pool: &PgPool, request: LoginRequest) -> Result<AuthResponse, ServiceError> {
        // валидируем email
        validation::validate_email(&request.email).map_err(ServiceError::ValidationFailed)?;
        
        // валидируем пароль
        validation::validate_password(&request.password).map_err(ServiceError::ValidationFailed)?;
        
        // находим пользователя по email
        let user = User::find_by_email(pool, &request.email)
            .await
            .map_err(ServiceError::DatabaseError)?
            .ok_or_else(|| ServiceError::Unauthorized("Invalid email or password".to_string()))?;
        
        // проверяем, активен ли пользователь
        if !user.is_active {
            return Err(ServiceError::Locked("User account is deactivated".to_string()));
        }
        
        // для полноценной реализации нужно хранить захешированный пароль пользователя в базе данных
        // сейчас мы просто возвращаем успешную аутентификацию для демонстрации
        let is_valid = true; // заглушка для демонстрации
        
        if !is_valid {
            return Err(ServiceError::Unauthorized("Invalid email or password".to_string()));
        }
        
        // генерируем jwt токен
        let token = generate_jwt_token(&user.id.to_string(), &user.role)?;
        
        Ok(AuthResponse {
            access_token: token,
            expires_in: 3600, // 1 час
            user,
        })
    }
}

// сервис пользователей
pub struct UserService;

impl UserService {
    // получение текущего пользователя
    pub async fn get_current_user(user_id: Uuid, pool: &PgPool) -> Result<User, ServiceError> {
        let user = User::find_by_id(pool, user_id)
            .await
            .map_err(ServiceError::DatabaseError)?
            .ok_or_else(|| ServiceError::NotFound("User not found".to_string()))?;
        
        Ok(user)
    }
    
    // обновление текущего пользователя
    pub async fn update_current_user(user_id: Uuid, request: UserUpdateRequest, pool: &PgPool) -> Result<User, ServiceError> {
        // валидируем полное имя
        validation::validate_full_name(&request.full_name).map_err(ServiceError::ValidationFailed)?;
        
        // валидируем возраст
        validation::validate_age(request.age).map_err(ServiceError::ValidationFailed)?;
        
        // валидируем регион
        validation::validate_region(request.region.clone()).map_err(ServiceError::ValidationFailed)?;
        
        // находим существующего пользователя
        let mut user = User::find_by_id(pool, user_id)
            .await
            .map_err(ServiceError::DatabaseError)?
            .ok_or_else(|| ServiceError::NotFound("User not found".to_string()))?;
        
        // проверяем, пытается ли обычный пользователь изменить роль или статус активности
        if user.role == UserRole::User {
            if request.role.is_some() {
                return Err(ServiceError::Forbidden("User cannot change role".to_string()));
            }
            if request.is_active.is_some() {
                return Err(ServiceError::Forbidden("User cannot change active status".to_string()));
            }
        }
        
        // обновляем поля пользователя
        user.full_name = request.full_name;
        user.age = request.age;
        user.region = request.region;
        user.gender = request.gender;
        user.marital_status = request.marital_status;
        
        // если пользователь администратор, он может изменить роль и статус активности
        if user.role == UserRole::Admin {
            if let Some(role) = request.role {
                user.role = role;
            }
            if let Some(is_active) = request.is_active {
                user.is_active = is_active;
            }
        }
        
        user.updated_at = Utc::now();
        
        // сохраняем обновленного пользователя
        let updated_user = User::update(pool, &user)
            .await
            .map_err(ServiceError::DatabaseError)?;
        
        Ok(updated_user)
    }
    
    // получение пользователя по id
    pub async fn get_user_by_id(target_user_id: Uuid, current_user_id: Uuid, current_user_role: &UserRole, pool: &PgPool) -> Result<User, ServiceError> {
        // если текущий пользователь не администратор и пытается получить чужой профиль
        if *current_user_role != UserRole::Admin && target_user_id != current_user_id {
            return Err(ServiceError::Forbidden("Access denied".to_string()));
        }
        
        let user = User::find_by_id(pool, target_user_id)
            .await
            .map_err(ServiceError::DatabaseError)?
            .ok_or_else(|| ServiceError::NotFound("User not found".to_string()))?;
        
        Ok(user)
    }
    
    // обновление пользователя по id
    pub async fn update_user_by_id(target_user_id: Uuid, request: UserUpdateRequest, current_user_id: Uuid, current_user_role: &UserRole, pool: &PgPool) -> Result<User, ServiceError> {
        // валидируем полное имя
        validation::validate_full_name(&request.full_name).map_err(ServiceError::ValidationFailed)?;
        
        // валидируем возраст
        validation::validate_age(request.age).map_err(ServiceError::ValidationFailed)?;
        
        // валидируем регион
        validation::validate_region(request.region.clone()).map_err(ServiceError::ValidationFailed)?;
        
        // если текущий пользователь не администратор и пытается обновить чужой профиль
        if *current_user_role != UserRole::Admin && target_user_id != current_user_id {
            return Err(ServiceError::Forbidden("Access denied".to_string()));
        }
        
        // находим существующего пользователя
        let mut user = User::find_by_id(pool, target_user_id)
            .await
            .map_err(ServiceError::DatabaseError)?
            .ok_or_else(|| ServiceError::NotFound("User not found".to_string()))?;
        
        // если обычный пользователь пытается изменить роль или статус активности
        if *current_user_role == UserRole::User && (request.role.is_some() || request.is_active.is_some()) {
            return Err(ServiceError::Forbidden("User cannot change role or active status".to_string()));
        }
        
        // обновляем поля пользователя
        user.full_name = request.full_name;
        user.age = request.age;
        user.region = request.region;
        user.gender = request.gender;
        user.marital_status = request.marital_status;
        
        // если текущий пользователь администратор, он может изменить роль и статус активности
        if *current_user_role == UserRole::Admin {
            if let Some(role) = request.role {
                user.role = role;
            }
            if let Some(is_active) = request.is_active {
                user.is_active = is_active;
            }
        }
        
        user.updated_at = Utc::now();
        
        // сохраняем обновленного пользователя
        let updated_user = User::update(pool, &user)
            .await
            .map_err(ServiceError::DatabaseError)?;
        
        Ok(updated_user)
    }
    
    // деактивация пользователя
    pub async fn deactivate_user(target_user_id: Uuid, current_user_id: Uuid, current_user_role: &UserRole, pool: &PgPool) -> Result<bool, ServiceError> {
        // только администратор может деактивировать пользователей
        if *current_user_role != UserRole::Admin {
            return Err(ServiceError::Forbidden("Only admin can deactivate users".to_string()));
        }
        
        // деактивируем пользователя
        let result = User::deactivate(pool, target_user_id)
            .await
            .map_err(ServiceError::DatabaseError)?;
        
        Ok(result)
    }
    
    // получение списка пользователей
    pub async fn get_all_users(current_user_role: &UserRole, page: i64, size: i64, pool: &PgPool) -> Result<PagedUsers, ServiceError> {
        // только администратор может просматривать всех пользователей
        if *current_user_role != UserRole::Admin {
            return Err(ServiceError::Forbidden("Only admin can view all users".to_string()));
        }
        
        // валидируем параметры пагинации
        validation::validate_pagination(Some(page), Some(size)).map_err(ServiceError::ValidationFailed)?;
        
        // получаем пользователей
        let paged_users = User::get_all_paginated(pool, page, size)
            .await
            .map_err(ServiceError::DatabaseError)?;
        
        Ok(paged_users)
    }
}

// сервис правил антифрода
pub struct FraudRuleService;

impl FraudRuleService {
    // создание нового правила
    pub async fn create_fraud_rule(request: FraudRuleCreateRequest, current_user_role: &UserRole, pool: &PgPool) -> Result<FraudRule, ServiceError> {
        // только администратор может создавать правила
        if *current_user_role != UserRole::Admin {
            return Err(ServiceError::Forbidden("Only admin can create fraud rules".to_string()));
        }
        
        // валидируем правило
        validation::validate_fraud_rule_create(&request).map_err(ServiceError::ValidationFailed)?;
        
        // проверяем, существует ли правило с таким именем
        // (реализация проверки дубликатов будет зависеть от конкретной логики)
        
        // создаем новое правило
        let now = Utc::now();
        let rule = FraudRule {
            id: Uuid::new_v4(),
            name: request.name,
            description: request.description,
            dsl_expression: request.dsl_expression,
            enabled: request.enabled,
            priority: request.priority,
            created_at: now,
            updated_at: now,
        };
        
        // сохраняем правило в базе данных
        let saved_rule = FraudRule::create(pool, &rule)
            .await
            .map_err(ServiceError::DatabaseError)?;
        
        Ok(saved_rule)
    }
    
    // получение всех правил
    pub async fn get_all_fraud_rules(current_user_role: &UserRole, pool: &PgPool) -> Result<Vec<FraudRule>, ServiceError> {
        // только администратор может просматривать все правила
        if *current_user_role != UserRole::Admin {
            return Err(ServiceError::Forbidden("Only admin can view all fraud rules".to_string()));
        }
        
        let rules = FraudRule::get_all(pool)
            .await
            .map_err(ServiceError::DatabaseError)?;
        
        Ok(rules)
    }
    
    // получение правила по id
    pub async fn get_fraud_rule_by_id(rule_id: Uuid, current_user_role: &UserRole, pool: &PgPool) -> Result<FraudRule, ServiceError> {
        // только администратор может просматривать правила
        if *current_user_role != UserRole::Admin {
            return Err(ServiceError::Forbidden("Only admin can view fraud rules".to_string()));
        }
        
        let rule = FraudRule::find_by_id(pool, rule_id)
            .await
            .map_err(ServiceError::DatabaseError)?
            .ok_or_else(|| ServiceError::NotFound("Fraud rule not found".to_string()))?;
        
        Ok(rule)
    }
    
    // обновление правила по id
    pub async fn update_fraud_rule_by_id(rule_id: Uuid, request: FraudRuleUpdateRequest, current_user_role: &UserRole, pool: &PgPool) -> Result<FraudRule, ServiceError> {
        // только администратор может обновлять правила
        if *current_user_role != UserRole::Admin {
            return Err(ServiceError::Forbidden("Only admin can update fraud rules".to_string()));
        }
        
        // валидируем правило
        validation::validate_fraud_rule_update(&request).map_err(ServiceError::ValidationFailed)?;
        
        // находим существующее правило
        let mut rule = FraudRule::find_by_id(pool, rule_id)
            .await
            .map_err(ServiceError::DatabaseError)?
            .ok_or_else(|| ServiceError::NotFound("Fraud rule not found".to_string()))?;
        
        // обновляем поля правила
        rule.name = request.name;
        rule.description = request.description;
        rule.dsl_expression = request.dsl_expression;
        rule.enabled = request.enabled;
        rule.priority = request.priority;
        rule.updated_at = Utc::now();
        
        // сохраняем обновленное правило
        let updated_rule = FraudRule::update(pool, &rule)
            .await
            .map_err(ServiceError::DatabaseError)?;
        
        Ok(updated_rule)
    }
    
    // деактивация правила
    pub async fn deactivate_fraud_rule(rule_id: Uuid, current_user_role: &UserRole, pool: &PgPool) -> Result<bool, ServiceError> {
        // только администратор может деактивировать правила
        if *current_user_role != UserRole::Admin {
            return Err(ServiceError::Forbidden("Only admin can deactivate fraud rules".to_string()));
        }
        
        let result = FraudRule::deactivate(pool, rule_id)
            .await
            .map_err(ServiceError::DatabaseError)?;
        
        Ok(result)
    }
    
    // валидация правила
    pub async fn validate_fraud_rule(request: FraudRuleValidateRequest) -> Result<FraudRuleValidateResponse, ServiceError> {
        // валидируем dsl выражение
        match dsl::validate_dsl(&request.dsl_expression) {
            Ok((is_valid, normalized)) => {
                Ok(FraudRuleValidateResponse {
                    is_valid,
                    normalized_expression: normalized,
                    errors: vec![], // если валидация прошла успешно, ошибок нет
                })
            },
            Err(errors) => {
                Ok(FraudRuleValidateResponse {
                    is_valid: false,
                    normalized_expression: None,
                    errors,
                })
            }
        }
    }
}

// сервис транзакций
pub struct TransactionService;

impl TransactionService {
    // создание новой транзакции
    pub async fn create_transaction(request: TransactionCreateRequest, current_user_id: Option<Uuid>, current_user_role: &UserRole, pool: &PgPool) -> Result<TransactionCreateResponse, ServiceError> {
        // валидируем транзакцию
        validation::validate_transaction_create(&request).map_err(ServiceError::ValidationFailed)?;
        
        // определяем user_id для транзакции
        let transaction_user_id = if *current_user_role == UserRole::Admin {
            // администратор может создавать транзакции для других пользователей
            request.user_id.ok_or_else(|| ServiceError::BadRequest("User ID is required for admin".to_string()))?
        } else {
            // обычный пользователь может создавать транзакции только для себя
            current_user_id.ok_or_else(|| ServiceError::Forbidden("Access denied".to_string()))?
        };
        
        // проверяем, существует ли пользователь
        let user = User::find_by_id(pool, transaction_user_id)
            .await
            .map_err(ServiceError::DatabaseError)?
            .ok_or_else(|| ServiceError::NotFound("User not found".to_string()))?;
        
        // проверяем, активен ли пользователь
        if !user.is_active {
            return Err(ServiceError::Forbidden("Cannot create transaction for inactive user".to_string()));
        }
        
        // создаем транзакцию
        let now = Utc::now();
        let transaction = Transaction {
            id: Uuid::new_v4(),
            user_id: transaction_user_id,
            amount: request.amount,
            currency: request.currency,
            status: TransactionStatus::Approved, // по умолчанию одобрена
            merchant_id: request.merchant_id,
            merchant_category_code: request.merchant_category_code,
            timestamp: request.timestamp,
            ip_address: request.ip_address,
            device_id: request.device_id,
            channel: request.channel,
            location: request.location,
            is_fraud: false, // пока не проверили правила
            metadata: request.metadata,
            created_at: now,
        };
        
        // сохраняем транзакцию
        let saved_transaction = Transaction::create(pool, &transaction)
            .await
            .map_err(ServiceError::DatabaseError)?;
        
        // применяем правила антифрода
        let rule_results = apply_fraud_rules(&saved_transaction, &user, pool).await?;
        
        // определяем статус транзакции на основе результатов правил
        let mut final_status = TransactionStatus::Approved;
        let mut is_fraud = false;
        
        for result in &rule_results {
            if result.matched {
                final_status = TransactionStatus::Declined;
                is_fraud = true;
                break;
            }
        }
        
        // обновляем статус транзакции в базе данных
        let mut updated_transaction = saved_transaction.clone();
        updated_transaction.status = final_status.clone();
        updated_transaction.is_fraud = is_fraud;
        
        // создаем ответ
        let response = TransactionCreateResponse {
            transaction: updated_transaction,
            rule_results,
        };
        
        Ok(response)
    }
    
    // применение правил антифрода к транзакции
    async fn apply_fraud_rules(transaction: &Transaction, user: &User, pool: &PgPool) -> Result<Vec<RuleResult>, ServiceError> {
        // получаем все активные правила
        let rules = FraudRule::get_all_enabled(pool)
            .await
            .map_err(ServiceError::DatabaseError)?;
        
        let mut rule_results = Vec::new();
        
        // применяем каждое правило к транзакции
        for rule in rules {
            // создаем контекст для оценки правила
            let context = RuleEvaluationContext {
                transaction,
                user,
                metadata: &transaction.metadata,
                timestamp: transaction.timestamp,
            };
            
            // по умолчанию результат false, так как мы реализуем Tier 0
            let mut matched = false;
            let mut description = format!("{} = {}, rule did not match", rule.dsl_expression, "false");
            
            // пытаемся распарсить и вычислить правило
            match dsl::parse_dsl(&rule.dsl_expression) {
                Ok(parsed_expr) => {
                    // если удалось распарсить, вычисляем выражение
                    matched = dsl::evaluate_expression(&parsed_expr, &context);
                    description = format!("{} = {}, rule {}", rule.dsl_expression, matched, if matched { "matched" } else { "did not match" });
                },
                Err(_) => {
                    // если не удалось распарсить, считаем, что правило не сработало
                    matched = false;
                    description = format!("Could not parse rule expression, rule did not match");
                }
            }
            
            // добавляем результат правила
            rule_results.push(RuleResult {
                rule_id: rule.id,
                rule_name: rule.name,
                priority: rule.priority,
                enabled: rule.enabled,
                matched,
                description,
            });
        }
        
        // сортируем результаты по приоритету и id
        rule_results.sort_by(|a, b| {
            a.priority.cmp(&b.priority)
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });
        
        Ok(rule_results)
    }
}

// функция для генерации jwt токена
fn generate_jwt_token(user_id: &str, role: &UserRole) -> Result<String, ServiceError> {
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| JWT_SECRET_KEY.to_string());
    
    let claims = JwtClaims {
        sub: user_id.to_string(),
        role: match role {
            UserRole::User => "USER".to_string(),
            UserRole::Admin => "ADMIN".to_string(),
        },
        exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
        iat: Utc::now().timestamp() as usize,
    };
    
    let token = encode(&Header::default(), &claims, &jsonwebtoken::EncodingKey::from_secret(secret.as_ref()))
        .map_err(|e| ServiceError::InternalServerError(e.to_string()))?;
    
    Ok(token)
}

// функция для валидации jwt токена
pub fn validate_jwt_token(token: &str) -> Result<JwtClaims, ServiceError> {
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| JWT_SECRET_KEY.to_string());
    
    let mut validation = Validation::default();
    validation.validate_exp = true;
    
    let token_data = decode::<JwtClaims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(secret.as_ref()),
        &validation,
    )
    .map_err(|e| ServiceError::Unauthorized(e.to_string()))?;
    
    Ok(token_data.claims)
}