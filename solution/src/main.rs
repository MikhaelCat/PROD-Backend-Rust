// модуль для веб-маршрутов
mod routes;
// модуль для моделей данных
mod models;
// модуль для работы с базой данных
mod database;
// модуль для бизнес-логики
mod services;
// модуль для ошибок
mod errors;
// модуль для валидации
mod validation;
// модуль для dsl-парсера
mod dsl;

use actix_web::{web, App, HttpServer, middleware::Logger};
use dotenv::dotenv;
use std::env;
use crate::database::establish_connection;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // загружаем переменные окружения из .env файла
    dotenv().ok();
    
    // настраиваем логирование
    env_logger::init();

    // получаем порт из переменных окружения или используем 8080 по умолчанию
    let port = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("PORT must be a number");

    // создаем соединение с базой данных
    let db_pool = establish_connection().await;

    // инициализируем администратора если он не существует
    initialize_admin_user(&db_pool).await;

    println!("Starting server on port {}", port);

    // запускаем http-сервер
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db_pool.clone()))
            .wrap(Logger::default())
            .configure(routes::config_services)
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}

// функция для инициализации администратора
async fn initialize_admin_user(pool: &sqlx::PgPool) {
    use crate::models::*;
    use crate::database::User;
    use bcrypt::{hash, DEFAULT_COST};
    use uuid::Uuid;
    use chrono::Utc;
    
    let admin_email = std::env::var("ADMIN_EMAIL").unwrap_or_else(|_| "admin@example.com".to_string());
    let admin_password = std::env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "admin123".to_string());
    let admin_fullname = std::env::var("ADMIN_FULLNAME").unwrap_or_else(|_| "Admin User".to_string());
    
    // проверяем, существует ли уже администратор
    if let Ok(Some(_)) = User::find_by_email(pool, &admin_email).await {
        println!("Admin user already exists");
        return;
    }
    
    // хешируем пароль
    let hashed_password = match hash(&admin_password, DEFAULT_COST) {
        Ok(hashed) => hashed,
        Err(e) => {
            eprintln!("Failed to hash admin password: {}", e);
            return;
        }
    };
    
    // создаем администратора
    let admin_user = User {
        id: Uuid::new_v4(),
        email: admin_email,
        full_name: admin_fullname,
        age: None,
        region: None,
        gender: None,
        marital_status: None,
        role: UserRole::Admin,
        is_active: true,
        password_hash: hashed_password,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    
    match User::create(pool, &admin_user).await {
        Ok(_) => println!("Admin user created successfully"),
        Err(e) => eprintln!("Failed to create admin user: {}", e),
    }
}
