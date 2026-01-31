#!/bin/bash
# =============================================================================
# Authentication API Test Script
# =============================================================================
# 测试用户认证相关的所有API endpoints
# =============================================================================

# set -e  # Disabled to allow test suite to run completely

BASE_URL="http://localhost:8000/api/v1"
CONTENT_TYPE="Content-Type: application/json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function to print test results
print_result() {
    local test_name="$1"
    local result="$2"
    if [ "$result" = "PASS" ]; then
        echo -e "${GREEN}[PASS]${NC} $test_name"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}[FAIL]${NC} $test_name"
        ((TESTS_FAILED++))
    fi
}

# Helper function to check HTTP status code
check_status() {
    local response="$1"
    local expected_status="$2"
    local actual_status=$(echo "$response" | grep -o '"status_code":[0-9]*' | grep -o '[0-9]*')
    [ "$actual_status" = "$expected_status" ]
}

echo "=========================================="
echo "Authentication API Test Suite"
echo "=========================================="
echo ""

# =============================================================================
# Test 1: User Registration
# =============================================================================
echo "--- Test 1: User Registration ---"

REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/register" \
    -H "$CONTENT_TYPE" \
    -d '{
        "email": "apitest@example.com",
        "password": "TestPass123",
        "username": "apitest"
    }')

# If user already exists, login instead
if echo "$REGISTER_RESPONSE" | grep -q "access_token"; then
    print_result "User registration returns access token" "PASS"
    TEST_ACCESS_TOKEN=$(echo "$REGISTER_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
    TEST_REFRESH_TOKEN=$(echo "$REGISTER_RESPONSE" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
elif echo "$REGISTER_RESPONSE" | grep -q '"status_code":409'; then
    print_result "User registration (user already exists, skipping)" "PASS"
    # Login to get tokens
    LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
        -H "$CONTENT_TYPE" \
        -d '{
            "email_or_username": "apitest@example.com",
            "password": "TestPass123"
        }')
    TEST_ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
    TEST_REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
else
    print_result "User registration returns access token" "FAIL"
fi

# Test duplicate registration
DUPLICATE_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/register" \
    -H "$CONTENT_TYPE" \
    -d '{
        "email": "apitest@example.com",
        "password": "TestPass123",
        "username": "apitest"
    }')

if check_status "$DUPLICATE_RESPONSE" "409"; then
    print_result "Duplicate registration returns 409 CONFLICT" "PASS"
else
    print_result "Duplicate registration returns 409 CONFLICT" "FAIL"
fi

echo ""

# =============================================================================
# Test 2: User Login
# =============================================================================
echo "--- Test 2: User Login ---"

# Login with username
LOGIN_USERNAME_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "$CONTENT_TYPE" \
    -d '{
        "username": "testuser",
        "password": "TestPass123"
    }')

if echo "$LOGIN_USERNAME_RESPONSE" | grep -q "access_token"; then
    print_result "Login with username" "PASS"
    LOGIN_ACCESS_TOKEN=$(echo "$LOGIN_USERNAME_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
else
    print_result "Login with username" "FAIL"
fi

# Login with email
LOGIN_EMAIL_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "$CONTENT_TYPE" \
    -d '{
        "email_or_username": "apitest@example.com",
        "password": "TestPass123"
    }')

if echo "$LOGIN_EMAIL_RESPONSE" | grep -q "access_token"; then
    print_result "Login with email" "PASS"
else
    print_result "Login with email" "FAIL"
fi

# Login with wrong password
WRONG_PASS_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "$CONTENT_TYPE" \
    -d '{
        "email_or_username": "apitest@example.com",
        "password": "WrongPassword123"
    }')

if check_status "$WRONG_PASS_RESPONSE" "401"; then
    print_result "Login with wrong password returns 401" "PASS"
else
    print_result "Login with wrong password returns 401" "FAIL"
fi

# Login with non-existent user
NONEXISTENT_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "$CONTENT_TYPE" \
    -d '{
        "email_or_username": "nonexistent@example.com",
        "password": "TestPass123"
    }')

if check_status "$NONEXISTENT_RESPONSE" "401"; then
    print_result "Login with non-existent user returns 401" "PASS"
else
    print_result "Login with non-existent user returns 401" "FAIL"
fi

echo ""

# =============================================================================
# Test 3: Get Current User Info
# =============================================================================
echo "--- Test 3: Get Current User Info ---"

ME_RESPONSE=$(curl -s -X GET "$BASE_URL/auth/me" \
    -H "Authorization: Bearer $TEST_ACCESS_TOKEN")

if echo "$ME_RESPONSE" | grep -q '"email":"apitest@example.com"'; then
    print_result "Get current user info" "PASS"
else
    print_result "Get current user info" "FAIL"
fi

# Test without token (should fail)
NO_TOKEN_RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/auth/me")
HTTP_STATUS=$(echo "$NO_TOKEN_RESPONSE" | tail -n1)

if [ "$HTTP_STATUS" = "401" ]; then
    print_result "Get user info without token returns 401" "PASS"
else
    print_result "Get user info without token returns 401" "FAIL"
fi

echo ""

# =============================================================================
# Test 4: Refresh Token
# =============================================================================
echo "--- Test 4: Refresh Token ---"

REFRESH_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/refresh" \
    -H "$CONTENT_TYPE" \
    -d "{\"refresh_token\": \"$TEST_REFRESH_TOKEN\"}")

if echo "$REFRESH_RESPONSE" | grep -q "access_token"; then
    print_result "Refresh access token" "PASS"
    NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
    NEW_REFRESH_TOKEN=$(echo "$REFRESH_RESPONSE" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
else
    print_result "Refresh access token" "FAIL"
fi

echo ""

# =============================================================================
# Test 5: Logout
# =============================================================================
echo "--- Test 5: Logout ---"

LOGOUT_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/logout" \
    -H "Authorization: Bearer $NEW_ACCESS_TOKEN" \
    -H "$CONTENT_TYPE" \
    -d "{\"refresh_token\": \"$NEW_REFRESH_TOKEN\"}")

if echo "$LOGOUT_RESPONSE" | grep -q "Successfully logged out"; then
    print_result "Logout successful" "PASS"
else
    print_result "Logout successful" "FAIL"
fi

# Test refresh token after logout (should fail)
REFRESH_AFTER_LOGOUT=$(curl -s -X POST "$BASE_URL/auth/refresh" \
    -H "$CONTENT_TYPE" \
    -d "{\"refresh_token\": \"$NEW_REFRESH_TOKEN\"}")

if check_status "$REFRESH_AFTER_LOGOUT" "404"; then
    print_result "Refresh token invalidated after logout" "PASS"
else
    print_result "Refresh token invalidated after logout" "FAIL"
fi

echo ""

# =============================================================================
# Test Summary
# =============================================================================
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo "Total: $((TESTS_PASSED + TESTS_FAILED))"
echo "=========================================="

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
