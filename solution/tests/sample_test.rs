// тестирование
#[cfg(test)]
mod tests {
    #[test]
    fn sample_test() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn another_sample_test() {
        let result = true;
        assert!(result, "This test passes");
    }
}

// интеграционый тест
#[test]
fn integration_test_example() {
    assert!(true);
}
