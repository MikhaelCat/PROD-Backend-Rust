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
