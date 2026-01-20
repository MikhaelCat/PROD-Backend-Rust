FROM rust:1.83-alpine AS builder

# зависимости для сборки
RUN apk add --no-cache musl-dev curl

WORKDIR /app

# копирование файлы проекта
COPY solution/Cargo.toml solution/Cargo.lock ./
COPY solution/src ./src
COPY solution/patches ./patches/ 

# сборка проект
RUN cargo build --release --locked

# конечный образ
FROM alpine:latest

# устанавливаем curl для health check
RUN apk add --no-cache curl

WORKDIR /app

COPY --from=builder /app/target/release/antifraud-backend /usr/local/bin/antifraud-backend

# проверка, что curl установлен
RUN which curl

EXPOSE 8080

CMD ["antifraud-backend"]
