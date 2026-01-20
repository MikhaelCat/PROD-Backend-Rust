// модуль для валидации данных

use crate::models::*;
use crate::errors::ValidationErrorField;

// валидация email
pub fn validate_email(email: &str) -> Result<(), Vec<ValidationErrorField>> {
    let mut errors = Vec::new();
    
    if email.is_empty() {
        errors.push(ValidationErrorField {
            field: "email".to_string(),
            message: "Email is required".to_string(),
            value: Some(email.to_string()),
        });
    } else if email.len() > 254 {
        errors.push(ValidationErrorField {
            field: "email".to_string(),
            message: "Email must be at most 254 characters".to_string(),
            value: Some(email.to_string()),
        });
    } else {
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
        if !email_regex.is_match(email) {
            errors.push(ValidationErrorField {
                field: "email".to_string(),
                message: "Invalid email format".to_string(),
                value: Some(email.to_string()),
            });
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// валидация пароля
pub fn validate_password(password: &str) -> Result<(), Vec<ValidationErrorField>> {
    let mut errors = Vec::new();

    if password.is_empty() {
        errors.push(ValidationErrorField {
            field: "password".to_string(),
            message: "Password is required".to_string(),
            value: Some(password.to_string()),
        });
    } else {
        if password.len() < 8 {
            errors.push(ValidationErrorField {
                field: "password".to_string(),
                message: "Password must be at least 8 characters".to_string(),
                value: Some(password.to_string()),
            });
        }
        if password.len() > 72 {
            errors.push(ValidationErrorField {
                field: "password".to_string(),
                message: "Password must be at most 72 characters".to_string(),
                value: Some(password.to_string()),
            });
        }
        if !password.chars().any(|c| c.is_alphabetic()) {
            errors.push(ValidationErrorField {
                field: "password".to_string(),
                message: "Password must contain at least one letter".to_string(),
                value: Some(password.to_string()),
            });
        }
        if !password.chars().any(|c| c.is_numeric()) {
            errors.push(ValidationErrorField {
                field: "password".to_string(),
                message: "Password must contain at least one digit".to_string(),
                value: Some(password.to_string()),
            });
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// валидация полного имени
pub fn validate_full_name(full_name: &str) -> Result<(), Vec<ValidationErrorField>> {
    let mut errors = Vec::new();

    if full_name.is_empty() {
        errors.push(ValidationErrorField {
            field: "fullName".to_string(),
            message: "Full name is required".to_string(),
            value: Some(full_name.to_string()),
        });
    } else if full_name.len() < 2 {
        errors.push(ValidationErrorField {
            field: "fullName".to_string(),
            message: "Full name must be at least 2 characters".to_string(),
            value: Some(full_name.to_string()),
        });
    } else if full_name.len() > 200 {
        errors.push(ValidationErrorField {
            field: "fullName".to_string(),
            message: "Full name must be at most 200 characters".to_string(),
            value: Some(full_name.to_string()),
        });
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// валидация возраста
pub fn validate_age(age: Option<i32>) -> Result<(), Vec<ValidationErrorField>> {
    let mut errors = Vec::new();

    if let Some(age_value) = age {
        if age_value < 18 {
            errors.push(ValidationErrorField {
                field: "age".to_string(),
                message: "Age must be at least 18".to_string(),
                value: age.map(|a| a.to_string()),
            });
        } else if age_value > 120 {
            errors.push(ValidationErrorField {
                field: "age".to_string(),
                message: "Age must be at most 120".to_string(),
                value: age.map(|a| a.to_string()),
            });
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// валидация региона
pub fn validate_region(region: Option<String>) -> Result<(), Vec<ValidationErrorField>> {
    let mut errors = Vec::new();

    if let Some(region_value) = region {
        if region_value.len() > 32 {
            errors.push(ValidationErrorField {
                field: "region".to_string(),
                message: "Region must be at most 32 characters".to_string(),
                value: Some(region_value),
            });
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// валидация правила антифрода
pub fn validate_fraud_rule_create(request: &FraudRuleCreateRequest) -> Result<(), Vec<ValidationErrorField>> {
    let mut errors = Vec::new();

    // валидация имени
    if request.name.is_empty() {
        errors.push(ValidationErrorField {
            field: "name".to_string(),
            message: "Name is required".to_string(),
            value: Some(request.name.clone()),
        });
    } else if request.name.len() < 3 {
        errors.push(ValidationErrorField {
            field: "name".to_string(),
            message: "Name must be at least 3 characters".to_string(),
            value: Some(request.name.clone()),
        });
    } else if request.name.len() > 120 {
        errors.push(ValidationErrorField {
            field: "name".to_string(),
            message: "Name must be at most 120 characters".to_string(),
            value: Some(request.name.clone()),
        });
    }

    // валидация описания
    if let Some(description) = &request.description {
        if description.len() > 500 {
            errors.push(ValidationErrorField {
                field: "description".to_string(),
                message: "Description must be at most 500 characters".to_string(),
                value: Some(description.clone()),
            });
        }
    }

    // валидация dsl выражения
    if request.dsl_expression.is_empty() {
        errors.push(ValidationErrorField {
            field: "dslExpression".to_string(),
            message: "DSL expression is required".to_string(),
            value: Some(request.dsl_expression.clone()),
        });
    } else if request.dsl_expression.len() < 3 {
        errors.push(ValidationErrorField {
            field: "dslExpression".to_string(),
            message: "DSL expression must be at least 3 characters".to_string(),
            value: Some(request.dsl_expression.clone()),
        });
    } else if request.dsl_expression.len() > 2000 {
        errors.push(ValidationErrorField {
            field: "dslExpression".to_string(),
            message: "DSL expression must be at most 2000 characters".to_string(),
            value: Some(request.dsl_expression.clone()),
        });
    }

    // валидация приоритета
    if request.priority < 1 {
        errors.push(ValidationErrorField {
            field: "priority".to_string(),
            message: "Priority must be at least 1".to_string(),
            value: Some(request.priority.to_string()),
        });
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// валидация обновления правила антифрода
pub fn validate_fraud_rule_update(request: &FraudRuleUpdateRequest) -> Result<(), Vec<ValidationErrorField>> {
    let mut errors = Vec::new();

    // валидация имени
    if request.name.is_empty() {
        errors.push(ValidationErrorField {
            field: "name".to_string(),
            message: "Name is required".to_string(),
            value: Some(request.name.clone()),
        });
    } else if request.name.len() < 3 {
        errors.push(ValidationErrorField {
            field: "name".to_string(),
            message: "Name must be at least 3 characters".to_string(),
            value: Some(request.name.clone()),
        });
    } else if request.name.len() > 120 {
        errors.push(ValidationErrorField {
            field: "name".to_string(),
            message: "Name must be at most 120 characters".to_string(),
            value: Some(request.name.clone()),
        });
    }

    // валидация описания
    if let Some(description) = &request.description {
        if description.len() > 500 {
            errors.push(ValidationErrorField {
                field: "description".to_string(),
                message: "Description must be at most 500 characters".to_string(),
                value: Some(description.clone()),
            });
        }
    }

    // валидация dsl выражения
    if request.dsl_expression.is_empty() {
        errors.push(ValidationErrorField {
            field: "dslExpression".to_string(),
            message: "DSL expression is required".to_string(),
            value: Some(request.dsl_expression.clone()),
        });
    } else if request.dsl_expression.len() < 3 {
        errors.push(ValidationErrorField {
            field: "dslExpression".to_string(),
            message: "DSL expression must be at least 3 characters".to_string(),
            value: Some(request.dsl_expression.clone()),
        });
    } else if request.dsl_expression.len() > 2000 {
        errors.push(ValidationErrorField {
            field: "dslExpression".to_string(),
            message: "DSL expression must be at most 2000 characters".to_string(),
            value: Some(request.dsl_expression.clone()),
        });
    }

    // валидация приоритета
    if request.priority < 1 {
        errors.push(ValidationErrorField {
            field: "priority".to_string(),
            message: "Priority must be at least 1".to_string(),
            value: Some(request.priority.to_string()),
        });
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// валидация создания транзакции
pub fn validate_transaction_create(request: &TransactionCreateRequest) -> Result<(), Vec<ValidationErrorField>> {
    let mut errors = Vec::new();

    // валидация суммы
    if request.amount < 0.01 || request.amount > 999999999.99 {
        errors.push(ValidationErrorField {
            field: "amount".to_string(),
            message: "Amount must be between 0.01 and 999999999.99".to_string(),
            value: Some(request.amount.to_string()),
        });
    }

    // валидация валюты
    if request.currency.len() != 3 || !request.currency.chars().all(|c| c.is_ascii_uppercase()) {
        errors.push(ValidationErrorField {
            field: "currency".to_string(),
            message: "Currency must be 3 uppercase letters (ISO 4217)".to_string(),
            value: Some(request.currency.clone()),
        });
    }

    // валидация merchant id
    if let Some(merchant_id) = &request.merchant_id {
        if merchant_id.len() > 64 {
            errors.push(ValidationErrorField {
                field: "merchantId".to_string(),
                message: "Merchant ID must be at most 64 characters".to_string(),
                value: Some(merchant_id.clone()),
            });
        }
    }

    // валидация merchant category code
    if let Some(mcc) = &request.merchant_category_code {
        if mcc.len() != 4 || !mcc.chars().all(|c| c.is_ascii_digit()) {
            errors.push(ValidationErrorField {
                field: "merchantCategoryCode".to_string(),
                message: "Merchant category code must be 4 digits".to_string(),
                value: Some(mcc.clone()),
            });
        }
    }

    // валидация ip адреса
    if let Some(ip) = &request.ip_address {
        if ip.len() > 64 {
            errors.push(ValidationErrorField {
                field: "ipAddress".to_string(),
                message: "IP address must be at most 64 characters".to_string(),
                value: Some(ip.clone()),
            });
        }
    }

    // валидация device id
    if let Some(device_id) = &request.device_id {
        if device_id.len() > 128 {
            errors.push(ValidationErrorField {
                field: "deviceId".to_string(),
                message: "Device ID must be at most 128 characters".to_string(),
                value: Some(device_id.clone()),
            });
        }
    }

    // валидация местоположения
    if let Some(location) = &request.location {
        if location.country.len() != 2 || !location.country.chars().all(|c| c.is_ascii_uppercase()) {
            errors.push(ValidationErrorField {
                field: "location.country".to_string(),
                message: "Country must be 2 uppercase letters (ISO 3166-1 alpha-2)".to_string(),
                value: Some(location.country.clone()),
            });
        }
        
        if location.city.len() > 128 {
            errors.push(ValidationErrorField {
                field: "location.city".to_string(),
                message: "City must be at most 128 characters".to_string(),
                value: Some(location.city.clone()),
            });
        }

        if let (Some(lat), Some(lng)) = (location.latitude, location.longitude) {
            if lat < -90.0 || lat > 90.0 {
                errors.push(ValidationErrorField {
                    field: "location.latitude".to_string(),
                    message: "Latitude must be between -90 and 90".to_string(),
                    value: Some(lat.to_string()),
                });
            }
            
            if lng < -180.0 || lng > 180.0 {
                errors.push(ValidationErrorField {
                    field: "location.longitude".to_string(),
                    message: "Longitude must be between -180 and 180".to_string(),
                    value: Some(lng.to_string()),
                });
            }
        } else if location.latitude.is_some() || location.longitude.is_some() {
            // если одна координата указана, другая тоже должна быть
            errors.push(ValidationErrorField {
                field: "location".to_string(),
                message: "Both latitude and longitude must be provided together".to_string(),
                value: None,
            });
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// валидация пагинации
pub fn validate_pagination(page: Option<i64>, size: Option<i64>) -> Result<(i64, i64), Vec<ValidationErrorField>> {
    let mut errors = Vec::new();
    
    let page_val = page.unwrap_or(0);
    let size_val = size.unwrap_or(20);
    
    if page_val < 0 {
        errors.push(ValidationErrorField {
            field: "page".to_string(),
            message: "Page must be at least 0".to_string(),
            value: Some(page_val.to_string()),
        });
    }
    
    if size_val < 1 {
        errors.push(ValidationErrorField {
            field: "size".to_string(),
            message: "Size must be at least 1".to_string(),
            value: Some(size_val.to_string()),
        });
    } else if size_val > 100 {
        errors.push(ValidationErrorField {
            field: "size".to_string(),
            message: "Size must be at most 100".to_string(),
            value: Some(size_val.to_string()),
        });
    }
    
    if errors.is_empty() {
        Ok((page_val, size_val))
    } else {
        Err(errors)
    }
}