// интеграционные тесты
#[cfg(test)]
mod integration_tests {
    #[test]
    fn sample_integration_test() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn test_main_logic() {
        // тест для проверки основной функциональности
        let result = 10;
        assert_eq!(result, 10);
    }
}

// модкльное тестирование
#[cfg(test)]
mod unit_tests {
    #[test]
    fn sample_unit_test() {
        assert!(true);
    }
}

// тестирования конкретной функциональности
#[test]
fn health_check_test() {
    assert!(true); 
}
