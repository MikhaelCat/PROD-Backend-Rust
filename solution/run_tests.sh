#!/bin/bash

# Script to run tests for the solution

echo "Running tests for the solution..."

# Option 1: Using Docker Compose (includes all services)
echo "Option 1: Running tests with full stack (using docker-compose)"
echo "docker-compose run --rm test-runner"

# Option 2: Using just Docker
echo "Option 2: Running tests in isolation (using docker only)"
echo "cd solution && docker build -t solution-tester . && docker run solution-tester"

echo ""
echo "To run tests with docker-compose (recommended):"
echo "  cd /workspace && docker-compose run --rm test-runner"

echo ""
echo "To run tests with just docker:"
echo "  cd /workspace/solution && docker build -t solution-tester . && docker run solution-tester"

echo ""
echo "To run specific tests:"
echo "  cd /workspace && docker-compose run --rm test-runner cargo test test_name --verbose"

echo ""
echo "All set! Your test environment is ready."