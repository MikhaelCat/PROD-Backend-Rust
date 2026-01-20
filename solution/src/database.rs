// модуль для работы с базой данных

use sqlx::{PgPool, Row};
use crate::models::*;
use uuid::Uuid;
use chrono::Utc;
use std::env;
use std::collections::HashMap;

// функция для установки соединения с базой данных
pub async fn establish_connection() -> PgPool {
    // получаем строку подключения из переменных окружения
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| {
            // если переменная окружения не установлена, используем стандартную строку подключения
            format!(
                "postgresql://{}:{}@{}:{}/{}",
                env::var("DB_USER").unwrap_or_else(|_| "postgres".to_string()),
                env::var("DB_PASSWORD").unwrap_or_else(|_| "postgres".to_string()),
                env::var("DB_HOST").unwrap_or_else(|_| "localhost".to_string()),
                env::var("DB_PORT").unwrap_or_else(|_| "5432".to_string()),
                env::var("DB_NAME").unwrap_or_else(|_| "testdb".to_string())
            )
        });
    
    // создаем пул соединений
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");
    
    // выполняем миграции
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");
    
    pool
}

// реализация методов для работы с пользователями
impl User {
    // создание нового пользователя
    pub async fn create(pool: &PgPool, user: &User) -> Result<User, sqlx::Error> {
        let query = r#"
            INSERT INTO users (id, email, full_name, age, region, gender, marital_status, role, is_active, password_hash, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id, email, full_name, age, region, gender, marital_status, role, is_active, password_hash, created_at, updated_at
        "#;
        
        let row = sqlx::query(query)
            .bind(user.id)
            .bind(&user.email)
            .bind(&user.full_name)
            .bind(user.age)
            .bind(&user.region)
            .bind(user.gender.as_ref().map(|g| match g {
                UserGender::Male => "MALE",
                UserGender::Female => "FEMALE",
            }))
            .bind(user.marital_status.as_ref().map(|ms| match ms {
                UserMaritalStatus::Single => "SINGLE",
                UserMaritalStatus::Married => "MARRIED",
                UserMaritalStatus::Divorced => "DIVORCED",
                UserMaritalStatus::Widowed => "WIDOWED",
            }))
            .bind(match user.role {
                UserRole::User => "USER",
                UserRole::Admin => "ADMIN",
            })
            .bind(user.is_active)
            .bind(&user.password_hash)
            .bind(user.created_at)
            .bind(user.updated_at)
            .fetch_one(pool)
            .await?;
        
        Ok(User {
            id: row.get("id"),
            email: row.get("email"),
            full_name: row.get("full_name"),
            age: row.get("age"),
            region: row.get("region"),
            gender: parse_gender(row.get::<Option<&str>, _>("gender")),
            marital_status: parse_marital_status(row.get::<Option<&str>, _>("marital_status")),
            role: parse_role(row.get::<&str, _>("role")),
            is_active: row.get("is_active"),
            password_hash: row.get("password_hash"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
    
    // поиск пользователя по email
    pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<User>, sqlx::Error> {
        let query = r#"
            SELECT id, email, full_name, age, region, gender, marital_status, role, is_active, password_hash, created_at, updated_at
            FROM users
            WHERE email = $1 AND is_active = true
        "#;
        
        if let Some(row) = sqlx::query(query)
            .bind(email)
            .fetch_optional(pool)
            .await?
        {
            Ok(Some(User {
                id: row.get("id"),
                email: row.get("email"),
                full_name: row.get("full_name"),
                age: row.get("age"),
                region: row.get("region"),
                gender: parse_gender(row.get::<Option<&str>, _>("gender")),
                marital_status: parse_marital_status(row.get::<Option<&str>, _>("marital_status")),
                role: parse_role(row.get::<&str, _>("role")),
                is_active: row.get("is_active"),
                password_hash: row.get("password_hash"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            }))
        } else {
            Ok(None)
        }
    }
    
    // поиск пользователя по id
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>, sqlx::Error> {
        let query = r#"
            SELECT id, email, full_name, age, region, gender, marital_status, role, is_active, password_hash, created_at, updated_at
            FROM users
            WHERE id = $1
        "#;
        
        if let Some(row) = sqlx::query(query)
            .bind(id)
            .fetch_optional(pool)
            .await?
        {
            Ok(Some(User {
                id: row.get("id"),
                email: row.get("email"),
                full_name: row.get("full_name"),
                age: row.get("age"),
                region: row.get("region"),
                gender: parse_gender(row.get::<Option<&str>, _>("gender")),
                marital_status: parse_marital_status(row.get::<Option<&str>, _>("marital_status")),
                role: parse_role(row.get::<&str, _>("role")),
                is_active: row.get("is_active"),
                password_hash: row.get("password_hash"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            }))
        } else {
            Ok(None)
        }
    }
    
    // обновление пользователя
    pub async fn update(pool: &PgPool, user: &User) -> Result<User, sqlx::Error> {
        let query = r#"
            UPDATE users 
            SET full_name = $1, age = $2, region = $3, gender = $4, marital_status = $5, role = $6, is_active = $7, updated_at = $8
            WHERE id = $9
        RETURNING id, email, full_name, age, region, gender, marital_status, role, is_active, password_hash, created_at, updated_at
        "#;
        
        let row = sqlx::query(query)
            .bind(&user.full_name)
            .bind(user.age)
            .bind(&user.region)
            .bind(user.gender.as_ref().map(|g| match g {
                UserGender::Male => "MALE",
                UserGender::Female => "FEMALE",
            }))
            .bind(user.marital_status.as_ref().map(|ms| match ms {
                UserMaritalStatus::Single => "SINGLE",
                UserMaritalStatus::Married => "MARRIED",
                UserMaritalStatus::Divorced => "DIVORCED",
                UserMaritalStatus::Widowed => "WIDOWED",
            }))
            .bind(match user.role {
                UserRole::User => "USER",
                UserRole::Admin => "ADMIN",
            })
            .bind(user.is_active)
            .bind(Utc::now())
            .bind(user.id)
            .fetch_one(pool)
            .await?;
        
        Ok(User {
            id: row.get("id"),
            email: row.get("email"),
            full_name: row.get("full_name"),
            age: row.get("age"),
            region: row.get("region"),
            gender: parse_gender(row.get::<Option<&str>, _>("gender")),
            marital_status: parse_marital_status(row.get::<Option<&str>, _>("marital_status")),
            role: parse_role(row.get::<&str, _>("role")),
            is_active: row.get("is_active"),
            password_hash: row.get("password_hash"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
    
    // деактивация пользователя
    pub async fn deactivate(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        let query = r#"
            UPDATE users 
            SET is_active = false, updated_at = $1
            WHERE id = $2
            RETURNING id
        "#;
        
        match sqlx::query(query)
            .bind(Utc::now())
            .bind(id)
            .fetch_optional(pool)
            .await?
        {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }
    
    // получение списка пользователей с пагинацией
    pub async fn get_all_paginated(pool: &PgPool, page: i64, size: i64) -> Result<PagedUsers, sqlx::Error> {
        let offset = page * size;
        
        // получаем записи пользователей
        let query = r#"
            SELECT id, email, full_name, age, region, gender, marital_status, role, is_active, password_hash, created_at, updated_at
            FROM users
            ORDER BY id
            LIMIT $1 OFFSET $2
        "#;
        
        let users_rows = sqlx::query(query)
            .bind(size)
            .bind(offset)
            .fetch_all(pool)
            .await?;
        
        // получаем общее количество пользователей
        let count_query = r#"SELECT COUNT(*) as total FROM users"#;
        let count_row = sqlx::query(count_query)
            .fetch_one(pool)
            .await?;
        let total: i64 = count_row.get("total");
        
        let users: Vec<User> = users_rows.into_iter().map(|row| User {
            id: row.get("id"),
            email: row.get("email"),
            full_name: row.get("full_name"),
            age: row.get("age"),
            region: row.get("region"),
            gender: parse_gender(row.get::<Option<&str>, _>("gender")),
            marital_status: parse_marital_status(row.get::<Option<&str>, _>("marital_status")),
            role: parse_role(row.get::<&str, _>("role")),
            is_active: row.get("is_active"),
            password_hash: row.get("password_hash"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }).collect();
        
        Ok(PagedUsers {
            items: users,
            total,
            page,
            size,
        })
    }
}

// реализация методов для работы с правилами антифрода
impl FraudRule {
    // создание нового правила
    pub async fn create(pool: &PgPool, rule: &FraudRule) -> Result<FraudRule, sqlx::Error> {
        let query = r#"
            INSERT INTO fraud_rules (id, name, description, dsl_expression, enabled, priority, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, name, description, dsl_expression, enabled, priority, created_at, updated_at
        "#;
        
        let row = sqlx::query(query)
            .bind(rule.id)
            .bind(&rule.name)
            .bind(&rule.description)
            .bind(&rule.dsl_expression)
            .bind(rule.enabled)
            .bind(rule.priority)
            .bind(rule.created_at)
            .bind(rule.updated_at)
            .fetch_one(pool)
            .await?;
        
        Ok(FraudRule {
            id: row.get("id"),
            name: row.get("name"),
            description: row.get("description"),
            dsl_expression: row.get("dsl_expression"),
            enabled: row.get("enabled"),
            priority: row.get("priority"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
    
    // получение всех активных правил
    pub async fn get_all_enabled(pool: &PgPool) -> Result<Vec<FraudRule>, sqlx::Error> {
        let query = r#"
            SELECT id, name, description, dsl_expression, enabled, priority, created_at, updated_at
            FROM fraud_rules
            WHERE enabled = true
            ORDER BY priority ASC, id ASC
        "#;
        
        let rows = sqlx::query(query)
            .fetch_all(pool)
            .await?;
        
        let rules: Vec<FraudRule> = rows.into_iter().map(|row| FraudRule {
            id: row.get("id"),
            name: row.get("name"),
            description: row.get("description"),
            dsl_expression: row.get("dsl_expression"),
            enabled: row.get("enabled"),
            priority: row.get("priority"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }).collect();
        
        Ok(rules)
    }
    
    // поиск правила по id
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<FraudRule>, sqlx::Error> {
        let query = r#"
            SELECT id, name, description, dsl_expression, enabled, priority, created_at, updated_at
            FROM fraud_rules
            WHERE id = $1
        "#;
        
        if let Some(row) = sqlx::query(query)
            .bind(id)
            .fetch_optional(pool)
            .await?
        {
            Ok(Some(FraudRule {
                id: row.get("id"),
                name: row.get("name"),
                description: row.get("description"),
                dsl_expression: row.get("dsl_expression"),
                enabled: row.get("enabled"),
                priority: row.get("priority"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            }))
        } else {
            Ok(None)
        }
    }
    
    // обновление правила
    pub async fn update(pool: &PgPool, rule: &FraudRule) -> Result<FraudRule, sqlx::Error> {
        let query = r#"
            UPDATE fraud_rules 
            SET name = $1, description = $2, dsl_expression = $3, enabled = $4, priority = $5, updated_at = $6
            WHERE id = $7
            RETURNING id, name, description, dsl_expression, enabled, priority, created_at, updated_at
        "#;
        
        let row = sqlx::query(query)
            .bind(&rule.name)
            .bind(&rule.description)
            .bind(&rule.dsl_expression)
            .bind(rule.enabled)
            .bind(rule.priority)
            .bind(Utc::now())
            .bind(rule.id)
            .fetch_one(pool)
            .await?;
        
        Ok(FraudRule {
            id: row.get("id"),
            name: row.get("name"),
            description: row.get("description"),
            dsl_expression: row.get("dsl_expression"),
            enabled: row.get("enabled"),
            priority: row.get("priority"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
    
    // деактивация правила (soft delete)
    pub async fn deactivate(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        let query = r#"
            UPDATE fraud_rules 
            SET enabled = false, updated_at = $1
            WHERE id = $2
            RETURNING id
        "#;
        
        match sqlx::query(query)
            .bind(Utc::now())
            .bind(id)
            .fetch_optional(pool)
            .await?
        {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }
    
    // получение всех правил
    pub async fn get_all(pool: &PgPool) -> Result<Vec<FraudRule>, sqlx::Error> {
        let query = r#"
            SELECT id, name, description, dsl_expression, enabled, priority, created_at, updated_at
            FROM fraud_rules
            ORDER BY priority ASC, id ASC
        "#;
        
        let rows = sqlx::query(query)
            .fetch_all(pool)
            .await?;
        
        let rules: Vec<FraudRule> = rows.into_iter().map(|row| FraudRule {
            id: row.get("id"),
            name: row.get("name"),
            description: row.get("description"),
            dsl_expression: row.get("dsl_expression"),
            enabled: row.get("enabled"),
            priority: row.get("priority"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }).collect();
        
        Ok(rules)
    }
}

// реализация методов для работы с транзакциями
impl Transaction {
    // создание новой транзакции
    pub async fn create(pool: &PgPool, transaction: &Transaction) -> Result<Transaction, sqlx::Error> {
        let query = r#"
            INSERT INTO transactions (id, user_id, amount, currency, status, merchant_id, merchant_category_code, 
                                     timestamp, ip_address, device_id, channel, location, is_fraud, metadata, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING id, user_id, amount, currency, status, merchant_id, merchant_category_code, 
                    timestamp, ip_address, device_id, channel, location, is_fraud, metadata, created_at
        "#;
        
        let row = sqlx::query(query)
            .bind(transaction.id)
            .bind(transaction.user_id)
            .bind(transaction.amount)
            .bind(&transaction.currency)
            .bind(match transaction.status {
                TransactionStatus::Approved => "APPROVED",
                TransactionStatus::Declined => "DECLINED",
            })
            .bind(&transaction.merchant_id)
            .bind(&transaction.merchant_category_code)
            .bind(transaction.timestamp)
            .bind(&transaction.ip_address)
            .bind(&transaction.device_id)
            .bind(transaction.channel.as_ref().map(|c| match c {
                TransactionChannel::Web => "WEB",
                TransactionChannel::Mobile => "MOBILE",
                TransactionChannel::Pos => "POS",
                TransactionChannel::Other => "OTHER",
            }))
            .bind(if let Some(ref loc) = transaction.location {
                Some(serde_json::to_string(loc).unwrap_or_default())
            } else {
                None
            })
            .bind(transaction.is_fraud)
            .bind(if let Some(ref meta) = transaction.metadata {
                Some(serde_json::to_string(meta).unwrap_or_default())
            } else {
                None
            })
            .bind(transaction.created_at)
            .fetch_one(pool)
            .await?;
        
        Ok(Transaction {
            id: row.get("id"),
            user_id: row.get("user_id"),
            amount: row.get("amount"),
            currency: row.get("currency"),
            status: parse_transaction_status(row.get::<&str, _>("status")),
            merchant_id: row.get("merchant_id"),
            merchant_category_code: row.get("merchant_category_code"),
            timestamp: row.get("timestamp"),
            ip_address: row.get("ip_address"),
            device_id: row.get("device_id"),
            channel: parse_transaction_channel(row.get::<Option<&str>, _>("channel")),
            location: parse_transaction_location(row.get::<Option<String>, _>("location")),
            is_fraud: row.get("is_fraud"),
            metadata: parse_metadata(row.get::<Option<String>, _>("metadata")),
            created_at: row.get("created_at"),
        })
    }
    
    // поиск транзакции по id
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Transaction>, sqlx::Error> {
        let query = r#"
            SELECT id, user_id, amount, currency, status, merchant_id, merchant_category_code, 
                   timestamp, ip_address, device_id, channel, location, is_fraud, metadata, created_at
            FROM transactions
            WHERE id = $1
        "#;
        
        if let Some(row) = sqlx::query(query)
            .bind(id)
            .fetch_optional(pool)
            .await?
        {
            Ok(Some(Transaction {
                id: row.get("id"),
                user_id: row.get("user_id"),
                amount: row.get("amount"),
                currency: row.get("currency"),
                status: parse_transaction_status(row.get::<&str, _>("status")),
                merchant_id: row.get("merchant_id"),
                merchant_category_code: row.get("merchant_category_code"),
                timestamp: row.get("timestamp"),
                ip_address: row.get("ip_address"),
                device_id: row.get("device_id"),
                channel: parse_transaction_channel(row.get::<Option<&str>, _>("channel")),
                location: parse_transaction_location(row.get::<Option<String>, _>("location")),
                is_fraud: row.get("is_fraud"),
                metadata: parse_metadata(row.get::<Option<String>, _>("metadata")),
                created_at: row.get("created_at"),
            }))
        } else {
            Ok(None)
        }
    }
    
    // получение транзакций пользователя
    pub async fn get_by_user_id(pool: &PgPool, user_id: Uuid, page: i64, size: i64) -> Result<Vec<Transaction>, sqlx::Error> {
        let offset = page * size;
        
        let query = r#"
            SELECT id, user_id, amount, currency, status, merchant_id, merchant_category_code, 
                   timestamp, ip_address, device_id, channel, location, is_fraud, metadata, created_at
            FROM transactions
            WHERE user_id = $1
            ORDER BY timestamp DESC
            LIMIT $2 OFFSET $3
        "#;
        
        let rows = sqlx::query(query)
            .bind(user_id)
            .bind(size)
            .bind(offset)
            .fetch_all(pool)
            .await?;
        
        let transactions: Vec<Transaction> = rows.into_iter().map(|row| Transaction {
            id: row.get("id"),
            user_id: row.get("user_id"),
            amount: row.get("amount"),
            currency: row.get("currency"),
            status: parse_transaction_status(row.get::<&str, _>("status")),
            merchant_id: row.get("merchant_id"),
            merchant_category_code: row.get("merchant_category_code"),
            timestamp: row.get("timestamp"),
            ip_address: row.get("ip_address"),
            device_id: row.get("device_id"),
            channel: parse_transaction_channel(row.get::<Option<&str>, _>("channel")),
            location: parse_transaction_location(row.get::<Option<String>, _>("location")),
            is_fraud: row.get("is_fraud"),
            metadata: parse_metadata(row.get::<Option<String>, _>("metadata")),
            created_at: row.get("created_at"),
        }).collect();
        
        Ok(transactions)
    }

    // получение транзакций с пагинацией (для администратора)
    pub async fn get_all_paginated(pool: &PgPool, page: i64, size: i64) -> Result<PagedTransactions, sqlx::Error> {
        let offset = page * size;
        
        let query = r#"
            SELECT id, user_id, amount, currency, status, merchant_id, merchant_category_code, 
                   timestamp, ip_address, device_id, channel, location, is_fraud, metadata, created_at
            FROM transactions
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
        "#;
        
        let rows = sqlx::query(query)
            .bind(size)
            .bind(offset)
            .fetch_all(pool)
            .await?;
        
        let transactions: Vec<Transaction> = rows.into_iter().map(|row| Transaction {
            id: row.get("id"),
            user_id: row.get("user_id"),
            amount: row.get("amount"),
            currency: row.get("currency"),
            status: parse_transaction_status(row.get::<&str, _>("status")),
            merchant_id: row.get("merchant_id"),
            merchant_category_code: row.get("merchant_category_code"),
            timestamp: row.get("timestamp"),
            ip_address: row.get("ip_address"),
            device_id: row.get("device_id"),
            channel: parse_transaction_channel(row.get::<Option<&str>, _>("channel")),
            location: parse_transaction_location(row.get::<Option<String>, _>("location")),
            is_fraud: row.get("is_fraud"),
            metadata: parse_metadata(row.get::<Option<String>, _>("metadata")),
            created_at: row.get("created_at"),
        }).collect();
        
        // получаем общее количество транзакций
        let count_query = r#"SELECT COUNT(*) as total FROM transactions"#;
        let count_row = sqlx::query(count_query)
            .fetch_one(pool)
            .await?;
        let total: i64 = count_row.get("total");
        
        Ok(PagedTransactions {
            items: transactions,
            total,
            page,
            size,
        })
    }

    // получение количества транзакций пользователя
    pub async fn count_by_user_id(pool: &PgPool, user_id: Uuid) -> Result<i64, sqlx::Error> {
        let query = r#"SELECT COUNT(*) as total FROM transactions WHERE user_id = $1"#;
        
        let row = sqlx::query(query)
            .bind(user_id)
            .fetch_one(pool)
            .await?;
            
        let total: i64 = row.get("total");
        
        Ok(total)
    }

    // получение результатов проверки правил для транзакции
    pub async fn get_rule_results_by_transaction_id(pool: &PgPool, transaction_id: Uuid) -> Result<Vec<RuleResult>, sqlx::Error> {
        let query = r#"
            SELECT rule_id, rule_name, priority, enabled, matched, description
            FROM transaction_rule_results
            WHERE transaction_id = $1
            ORDER BY priority ASC, rule_id ASC
        "#;
        
        let rows = sqlx::query(query)
            .bind(transaction_id)
            .fetch_all(pool)
            .await?;
        
        let rule_results: Vec<RuleResult> = rows.into_iter().map(|row| RuleResult {
            rule_id: row.get("rule_id"),
            rule_name: row.get("rule_name"),
            priority: row.get("priority"),
            enabled: row.get("enabled"),
            matched: row.get("matched"),
            description: row.get("description"),
        }).collect();
        
        Ok(rule_results)
    }

    // сохранение результатов проверки правил для транзакции
    pub async fn save_rule_results_for_transaction(pool: &PgPool, transaction_id: Uuid, rule_results: &[RuleResult]) -> Result<(), sqlx::Error> {
        for result in rule_results {
            let query = r#"
                INSERT INTO transaction_rule_results (id, transaction_id, rule_id, rule_name, priority, enabled, matched, description, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#;
            
            sqlx::query(query)
                .bind(uuid::Uuid::new_v4())
                .bind(transaction_id)
                .bind(result.rule_id)
                .bind(&result.rule_name)
                .bind(result.priority)
                .bind(result.enabled)
                .bind(result.matched)
                .bind(&result.description)
                .bind(chrono::Utc::now())
                .execute(pool)
                .await?;
        }
        
        Ok(())
    }
}

// вспомогательные функции для парсинга enum значений
fn parse_gender(gender_str: Option<&str>) -> Option<UserGender> {
    match gender_str {
        Some("MALE") => Some(UserGender::Male),
        Some("FEMALE") => Some(UserGender::Female),
        _ => None,
    }
}

fn parse_marital_status(status_str: Option<&str>) -> Option<UserMaritalStatus> {
    match status_str {
        Some("SINGLE") => Some(UserMaritalStatus::Single),
        Some("MARRIED") => Some(UserMaritalStatus::Married),
        Some("DIVORCED") => Some(UserMaritalStatus::Divorced),
        Some("WIDOWED") => Some(UserMaritalStatus::Widowed),
        _ => None,
    }
}

fn parse_role(role_str: &str) -> UserRole {
    match role_str {
        "USER" => UserRole::User,
        "ADMIN" => UserRole::Admin,
        _ => UserRole::User, // по умолчанию
    }
}

fn parse_transaction_status(status_str: &str) -> TransactionStatus {
    match status_str {
        "APPROVED" => TransactionStatus::Approved,
        "DECLINED" => TransactionStatus::Declined,
        _ => TransactionStatus::Approved, // по умолчанию
    }
}

fn parse_transaction_channel(channel_str: Option<&str>) -> Option<TransactionChannel> {
    match channel_str {
        Some("WEB") => Some(TransactionChannel::Web),
        Some("MOBILE") => Some(TransactionChannel::Mobile),
        Some("POS") => Some(TransactionChannel::Pos),
        Some("OTHER") => Some(TransactionChannel::Other),
        _ => None,
    }
}

fn parse_transaction_location(location_str: Option<String>) -> Option<TransactionLocation> {
    if let Some(location_json) = location_str {
        if let Ok(location) = serde_json::from_str::<TransactionLocation>(&location_json) {
            return Some(location);
        }
    }
    None
}

fn parse_metadata(metadata_str: Option<String>) -> Option<HashMap<String, serde_json::Value>> {
    if let Some(metadata_json) = metadata_str {
        if let Ok(metadata) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&metadata_json) {
            return Some(metadata);
        }
    }
    None
}