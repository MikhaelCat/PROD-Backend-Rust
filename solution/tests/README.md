# Tests Directory

This directory contains all the test files for the solution project.

## Types of Tests

- **Unit Tests**: Test individual functions and modules (typically located in the same file as the code they test)
- **Integration Tests**: Test the interaction between multiple components (located in this directory)

## Running Tests

### Local Testing

To run all tests locally:

```bash
cargo test
```

To run specific test:

```bash
cargo test test_name
```

To run tests with more verbose output:

```bash
cargo test -- --nocapture
```

### Docker Testing

To run tests using Docker:

```bash
# Build the Docker image
docker build -t solution-tester .

# Run the tests
docker run solution-tester
```

### Docker Compose (if available in root)

```bash
docker-compose -f docker-compose.test.yaml up --build
```

## Test Organization

- `integration_tests.rs`: Contains integration tests that test multiple components working together
- Other files: Additional test files organized by feature or module

## Adding New Tests

When adding new tests:
1. Place integration tests in this directory
2. Follow Rust testing conventions
3. Use descriptive names for test functions
4. Include proper assertions to validate expected behavior