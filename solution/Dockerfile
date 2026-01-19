FROM rust:1.83-alpine AS builder

# Устанавливаем зависимости для сборки
RUN apk add --no-cache musl-dev curl

WORKDIR /app

# Копируем файлы проекта
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Собираем проект
RUN cargo build --release --locked

# Итоговый образ
FROM alpine:latest

# Устанавливаем curl для health check
RUN apk add --no-cache curl

WORKDIR /app

# Копируем исполняемый файл из builder образа
COPY --from=builder /app/target/release/antifraud-backend /usr/local/bin/antifraud-backend

# Проверяем, что curl установлен
RUN which curl

EXPOSE 8080

CMD ["antifraud-backend"]