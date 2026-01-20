-- Создание таблицы пользователей
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email VARCHAR(254) UNIQUE NOT NULL,
    full_name VARCHAR(200) NOT NULL,
    age INTEGER,
    region VARCHAR(32),
    gender VARCHAR(10),
    marital_status VARCHAR(20),
    role VARCHAR(20) NOT NULL DEFAULT 'USER',
    is_active BOOLEAN NOT NULL DEFAULT true,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Создание таблицы правил антифрода
CREATE TABLE IF NOT EXISTS fraud_rules (
    id UUID PRIMARY KEY,
    name VARCHAR(120) UNIQUE NOT NULL,
    description TEXT,
    dsl_expression TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 100,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Создание таблицы транзакций
CREATE TABLE IF NOT EXISTS transactions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    amount DECIMAL(12,2) NOT NULL,
    currency VARCHAR(3) NOT NULL,
    status VARCHAR(20) NOT NULL,
    merchant_id VARCHAR(64),
    merchant_category_code VARCHAR(4),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    ip_address VARCHAR(64),
    device_id VARCHAR(128),
    channel VARCHAR(20),
    location TEXT,
    is_fraud BOOLEAN NOT NULL DEFAULT false,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Создание таблицы результатов проверки правил для транзакций
CREATE TABLE IF NOT EXISTS transaction_rule_results (
    id UUID PRIMARY KEY,
    transaction_id UUID NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    rule_id UUID NOT NULL REFERENCES fraud_rules(id),
    rule_name VARCHAR(120) NOT NULL,
    priority INTEGER NOT NULL,
    enabled BOOLEAN NOT NULL,
    matched BOOLEAN NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);