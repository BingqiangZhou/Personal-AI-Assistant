#!/bin/bash

# Comprehensive Flutter Test Runner
# Runs all created tests to validate the mobile application

echo "================================================"
echo "Flutter Mobile App - Comprehensive Test Suite"
echo "================================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if Flutter is available
if ! command -v flutter &> /dev/null; then
    echo -e "${RED}Error: Flutter is not installed or not in PATH${NC}"
    exit 1
fi

echo "1. Flutter Doctor Check"
echo "----------------------"
flutter doctor
echo ""

echo "2. Analyze Project"
echo "------------------"
cd "$(dirname "$0")/.."
flutter analyze

echo ""
echo "3. Run Unit Tests"
echo "------------------"
echo "Running authentication service tests..."
flutter test test/services/auth_service_test.dart

echo ""
echo "Running assistant service tests..."
flutter test test/services/assistant_service_test.dart

echo ""
echo "Running knowledge service tests..."
flutter test test/services/knowledge_service_test.dart

echo ""
echo "Running podcast service tests..."
flutter test test/services/podcast_service_test.dart

echo ""
echo "Running provider tests..."
flutter test test/providers/auth_provider_test.dart

echo ""
echo "Running router tests..."
flutter test test/routers/router_test.dart

echo ""
echo "4. Run Integration Tests"
echo "------------------------"
echo "Running API integration tests..."
flutter test test/integration/api_integration_test.dart

echo ""
echo "Running user flow tests..."
flutter test test/integration/user_flow_test.dart

echo ""
echo "Running complete widget test..."
flutter test test/widget_test.dart

echo ""
echo "5. Generate Coverage Report"
echo "---------------------------"
flutter test --coverage

if command -v genhtml &> /dev/null; then
    echo "Generating HTML coverage report..."
    genhtml coverage/lcov.info -o coverage/html
    echo "Coverage report generated at: coverage/html/index.html"
fi

echo ""
echo "================================================"
echo "All tests completed!"
echo "================================================"
