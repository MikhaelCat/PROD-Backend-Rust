// модуль для парсинга и вычисления dsl выражений

use crate::models::RuleEvaluationContext;

// тип для представления ast выражения
#[derive(Debug, Clone)]
pub enum Expression {
    Binary {
        left: Box<Expression>,
        op: BinaryOp,
        right: Box<Expression>,
    },
    Unary {
        op: UnaryOp,
        expr: Box<Expression>,
    },
    Comparison {
        field: Field,
        op: ComparisonOp,
        value: Value,
    },
    Group(Box<Expression>),
}

// тип для бинарных операторов
#[derive(Debug, Clone)]
pub enum BinaryOp {
    And,
    Or,
}

// тип для унарных операторов
#[derive(Debug, Clone)]
pub enum UnaryOp {
    Not,
}

// тип для полей
#[derive(Debug, Clone)]
pub enum Field {
    Amount,
    Currency,
    MerchantId,
    IpAddress,
    DeviceId,
    UserAge,
    UserRegion,
}

// тип для операторов сравнения
#[derive(Debug, Clone)]
pub enum ComparisonOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

// тип для значений
#[derive(Debug, Clone)]
pub enum Value {
    Number(f64),
    String(String),
}

// результат парсинга
#[derive(Debug)]
pub enum ParseResult<T> {
    Ok(T),
    Error(String, usize, String), // сообщение, позиция, контекст
}

// функция для парсинга dsl выражения
pub fn parse_dsl(expression: &str) -> Result<Expression, Vec<String>> {
    let tokens = tokenize(expression)?;
    let mut parser = Parser::new(tokens);
    let result = parser.parse().map_err(|e| vec![e])?;
    
    // если остались токены, значит ошибка
    if !parser.tokens.is_empty() {
        return Err(vec!["Unexpected token".to_string()]);
    }
    
    Ok(result)
}

// функция для вычисления выражения
pub fn evaluate_expression(expr: &Expression, context: &RuleEvaluationContext) -> bool {
    match expr {
        Expression::Binary { left, op, right } => {
            let left_val = evaluate_expression(left, context);
            let right_val = evaluate_expression(right, context);
            
            match op {
                BinaryOp::And => left_val && right_val,
                BinaryOp::Or => left_val || right_val,
            }
        },
        Expression::Unary { op, expr } => {
            let val = evaluate_expression(expr, context);
            match op {
                UnaryOp::Not => !val,
            }
        },
        Expression::Comparison { field, op, value } => {
            compare_field_to_value(field, op, value, context)
        },
        Expression::Group(inner) => evaluate_expression(inner, context),
    }
}

// функция для сравнения поля со значением
fn compare_field_to_value(field: &Field, op: &ComparisonOp, value: &Value, context: &RuleEvaluationContext) -> bool {
    match field {
        Field::Amount => {
            if let Value::Number(expected_amount) = value {
                if let ComparisonOp::Eq = op {
                    (context.transaction.amount - expected_amount).abs() < f64::EPSILON
                } else {
                    let actual_amount = context.transaction.amount;
                    match op {
                        ComparisonOp::Eq => (actual_amount - expected_amount).abs() < f64::EPSILON,
                        ComparisonOp::Ne => (actual_amount - expected_amount).abs() >= f64::EPSILON,
                        ComparisonOp::Lt => actual_amount < *expected_amount,
                        ComparisonOp::Le => actual_amount <= *expected_amount,
                        ComparisonOp::Gt => actual_amount > *expected_amount,
                        ComparisonOp::Ge => actual_amount >= *expected_amount,
                    }
                }
            } else {
                false // ошибка типа
            }
        },
        Field::Currency => {
            if let Value::String(expected_currency) = value {
                match op {
                    ComparisonOp::Eq => context.transaction.currency == *expected_currency,
                    ComparisonOp::Ne => context.transaction.currency != *expected_currency,
                    _ => false, // операторы сравнения не применимы к строкам
                }
            } else {
                false // ошибка типа
            }
        },
        Field::MerchantId => {
            if let Value::String(expected_merchant_id) = value {
                match op {
                    ComparisonOp::Eq => context.transaction.merchant_id.as_ref().map_or(false, |id| id == expected_merchant_id),
                    ComparisonOp::Ne => context.transaction.merchant_id.as_ref().map_or(true, |id| id != expected_merchant_id),
                    _ => false, // операторы сравнения не применимы к строкам
                }
            } else {
                false // ошибка типа
            }
        },
        Field::IpAddress => {
            if let Value::String(expected_ip) = value {
                match op {
                    ComparisonOp::Eq => context.transaction.ip_address.as_ref().map_or(false, |ip| ip == expected_ip),
                    ComparisonOp::Ne => context.transaction.ip_address.as_ref().map_or(true, |ip| ip != expected_ip),
                    _ => false, // операторы сравнения не применимы к строкам
                }
            } else {
                false // ошибка типа
            }
        },
        Field::DeviceId => {
            if let Value::String(expected_device_id) = value {
                match op {
                    ComparisonOp::Eq => context.transaction.device_id.as_ref().map_or(false, |id| id == expected_device_id),
                    ComparisonOp::Ne => context.transaction.device_id.as_ref().map_or(true, |id| id != expected_device_id),
                    _ => false, // операторы сравнения не применимы к строкам
                }
            } else {
                false // ошибка типа
            }
        },
        Field::UserAge => {
            if let Value::Number(expected_age) = value {
                if let Some(user_age) = context.user.age {
                    match op {
                        ComparisonOp::Eq => (user_age as f64 - expected_age).abs() < f64::EPSILON,
                        ComparisonOp::Ne => (user_age as f64 - expected_age).abs() >= f64::EPSILON,
                        ComparisonOp::Lt => (user_age as f64) < *expected_age,
                        ComparisonOp::Le => (user_age as f64) <= *expected_age,
                        ComparisonOp::Gt => (user_age as f64) > *expected_age,
                        ComparisonOp::Ge => (user_age as f64) >= *expected_age,
                    }
                } else {
                    false // если возраст пользователя null, результат всегда false
                }
            } else {
                false // ошибка типа
            }
        },
        Field::UserRegion => {
            if let Value::String(expected_region) = value {
                match op {
                    ComparisonOp::Eq => context.user.region.as_ref().map_or(false, |region| region == expected_region),
                    ComparisonOp::Ne => context.user.region.as_ref().map_or(true, |region| region != expected_region),
                    _ => false, // операторы сравнения не применимы к строкам
                }
            } else {
                false // ошибка типа
            }
        },
    }
}

// токены для парсера
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Word(String),        // идентификаторы, ключевые слова
    Number(f64),
    String(String),
    Operator(String),
    LeftParen,
    RightParen,
    Whitespace,
    Eof,
}

// структура парсера
struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }
    
    fn current(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }
    
    fn advance(&mut self) -> Option<&Token> {
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        self.current()
    }
    
    fn expect(&mut self, expected: Token) -> Result<(), String> {
        if let Some(token) = self.current() {
            if *token == expected {
                self.advance();
                Ok(())
            } else {
                Err(format!("Expected {:?}, found {:?}", expected, token))
            }
        } else {
            Err(format!("Expected {:?}, found EOF", expected))
        }
    }
    
    fn parse(&mut self) -> Result<Expression, String> {
        self.parse_or()
    }
    
    fn parse_or(&mut self) -> Result<Expression, String> {
        let mut left = self.parse_and()?;
        
        while let Some(Token::Word(op)) = self.current() {
            if op.to_uppercase() == "OR" {
                self.advance(); // consume "OR"
                let right = self.parse_and()?;
                left = Expression::Binary {
                    left: Box::new(left),
                    op: BinaryOp::Or,
                    right: Box::new(right),
                };
            } else {
                break;
            }
        }
        
        Ok(left)
    }
    
    fn parse_and(&mut self) -> Result<Expression, String> {
        let mut left = self.parse_not()?;
        
        while let Some(Token::Word(op)) = self.current() {
            if op.to_uppercase() == "AND" {
                self.advance(); // consume "AND"
                let right = self.parse_not()?;
                left = Expression::Binary {
                    left: Box::new(left),
                    op: BinaryOp::And,
                    right: Box::new(right),
                };
            } else {
                break;
            }
        }
        
        Ok(left)
    }
    
    fn parse_not(&mut self) -> Result<Expression, String> {
        if let Some(Token::Word(op)) = self.current() {
            if op.to_uppercase() == "NOT" {
                self.advance(); // consume "NOT"
                let expr = self.parse_comparison()?;
                return Ok(Expression::Unary {
                    op: UnaryOp::Not,
                    expr: Box::new(expr),
                });
            }
        }
        
        self.parse_comparison()
    }
    
    fn parse_comparison(&mut self) -> Result<Expression, String> {
        // сначала пробуем распознать поле
        let field = match self.current() {
            Some(Token::Word(s)) => {
                match s.as_str() {
                    "amount" => Field::Amount,
                    "currency" => Field::Currency,
                    "merchantId" => Field::MerchantId,
                    "ipAddress" => Field::IpAddress,
                    "deviceId" => Field::DeviceId,
                    "user.age" => Field::UserAge,
                    "user.region" => Field::UserRegion,
                    _ => return Err(format!("Unknown field: {}", s)),
                }
            },
            _ => return Err("Expected field name".to_string()),
        };
        
        self.advance(); // consume field
        
        // затем оператор
        let op = match self.current() {
            Some(Token::Operator(s)) => {
                match s.as_str() {
                    "=" => ComparisonOp::Eq,
                    "!=" => ComparisonOp::Ne,
                    "<" => ComparisonOp::Lt,
                    "<=" => ComparisonOp::Le,
                    ">" => ComparisonOp::Gt,
                    ">=" => ComparisonOp::Ge,
                    _ => return Err(format!("Unknown comparison operator: {}", s)),
                }
            },
            _ => return Err("Expected comparison operator".to_string()),
        };
        
        self.advance(); // consume operator
        
        // затем значение
        let value = match self.current() {
            Some(Token::Number(n)) => Value::Number(*n),
            Some(Token::String(s)) => Value::String(s.clone()),
            _ => return Err("Expected value".to_string()),
        };
        
        self.advance(); // consume value
        
        Ok(Expression::Comparison {
            field,
            op,
            value,
        })
    }
    
    fn parse_group(&mut self) -> Result<Expression, String> {
        self.expect(Token::LeftParen)?;
        let expr = self.parse_or()?;
        self.expect(Token::RightParen)?;
        Ok(Expression::Group(Box::new(expr)))
    }
}

// функция для токенизации строки
fn tokenize(input: &str) -> Result<Vec<Token>, Vec<String>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    
    while i < chars.len() {
        let c = chars[i];
        
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                tokens.push(Token::Whitespace);
                i += 1;
            },
            '(' => {
                tokens.push(Token::LeftParen);
                i += 1;
            },
            ')' => {
                tokens.push(Token::RightParen);
                i += 1;
            },
            '\'' => {
                // строка в одинарных кавычках
                let _start = i;
                i += 1; // skip opening quote
                
                let mut value = String::new();
                while i < chars.len() && chars[i] != '\'' {
                    value.push(chars[i]);
                    i += 1;
                }
                
                if i >= chars.len() {
                    return Err(vec!["Unterminated string literal".to_string()]);
                }
                
                i += 1; // skip closing quote
                tokens.push(Token::String(value));
            },
            '=' | '!' | '<' | '>' => {
                // операторы
                let _start = i;
                let mut op = String::new();
                op.push(c);
                
                // проверяем на составные операторы
                if i + 1 < chars.len() && (c == '!' || c == '<' || c == '>') {
                    if chars[i + 1] == '=' {
                        op.push('=');
                        i += 2;
                    } else {
                        i += 1;
                    }
                } else {
                    i += 1;
                }
                
                tokens.push(Token::Operator(op));
            },
            '0'..='9' => {
                // число
                let _start = i;
                let mut num_str = String::new();
                
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    num_str.push(chars[i]);
                    i += 1;
                }
                
                match num_str.parse::<f64>() {
                    Ok(num) => tokens.push(Token::Number(num)),
                    Err(_) => return Err(vec!["Invalid number format".to_string()]),
                }
            },
            _ if c.is_alphabetic() || c == '.' => {
                // слово (идентификатор или ключевое слово)
                let _start = i;
                let mut word = String::new();
                
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '.') {
                    word.push(chars[i]);
                    i += 1;
                }
                
                tokens.push(Token::Word(word));
            },
            _ => {
                return Err(vec![format!("Unexpected character: {}", c)]);
            },
        }
    }
    
    tokens.push(Token::Eof);
    Ok(tokens)
}

// функция для получения контекста вокруг ошибки
fn get_near_context(input: &str, pos: usize) -> String {
    let chars: Vec<char> = input.chars().collect();
    let start = if pos >= 2 { pos - 2 } else { 0 };
    let end = std::cmp::min(pos + 2, chars.len());
    
    chars[start..end].iter().collect()
}

// функция для валидации dsl выражения
pub fn validate_dsl(expression: &str) -> Result<(bool, Option<String>), Vec<String>> {
    match parse_dsl(expression) {
        Ok(_) => {
            let normalized = normalize_expression(expression);
            Ok((true, Some(normalized)))
        },
        Err(_errors) => Ok((false, None)),
    }
}

// функция для нормализации выражения
fn normalize_expression(expr: &str) -> String {
    // простая нормализация: приведение к верхнему регистру для ключевых слов и добавление пробелов вокруг операторов
    let mut result = expr.to_string();
    
    // заменяем and/or/not на верхний регистр
    result = regex::Regex::new(r"\b(and|or|not)\b").unwrap()
        .replace_all(&result, |caps: &regex::Captures| caps[1].to_uppercase())
        .to_string();
    
    // добавляем пробелы вокруг бинарных операторов
    result = regex::Regex::new(r"([<>!=]=|[<>])").unwrap()
        .replace_all(&result, |caps: &regex::Captures| format!(" {} ", &caps[0]))
        .to_string();
    
    // удаляем лишние пробелы
    result = regex::Regex::new(r"\s+").unwrap()
        .replace_all(&result, " ")
        .trim()
        .to_string();
    
    result
}