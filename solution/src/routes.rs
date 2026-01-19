// импортируем необходимые зависимости
use actix_web::{web, Scope};

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

// заглушка для остальных обработчиков - они будут реализованы позже
#[actix_web::post("/auth/register")]
async fn register_handler() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::post("/auth/login")]
async fn login_handler() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::get("/users/me")]
async fn get_current_user() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::put("/users/me")]
async fn update_current_user() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::get("/users/{id}")]
async fn get_user_by_id() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::put("/users/{id}")]
async fn update_user_by_id() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::delete("/users/{id}")]
async fn delete_user_by_id() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::get("/users")]
async fn get_users_list() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::post("/users")]
async fn create_user_admin() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::post("/fraud-rules")]
async fn create_fraud_rule() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::get("/fraud-rules")]
async fn get_fraud_rules() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::get("/fraud-rules/{id}")]
async fn get_fraud_rule_by_id() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::put("/fraud-rules/{id}")]
async fn update_fraud_rule_by_id() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::delete("/fraud-rules/{id}")]
async fn delete_fraud_rule_by_id() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::post("/fraud-rules/validate")]
async fn validate_fraud_rule() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::post("/transactions")]
async fn create_transaction() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::get("/transactions")]
async fn get_transactions() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::get("/transactions/{id}")]
async fn get_transaction_by_id() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}

#[actix_web::post("/transactions/batch")]
async fn create_transactions_batch() -> impl actix_web::Responder {
    actix_web::HttpResponse::NotImplemented().json(serde_json::json!({"error": "not implemented"}))
}