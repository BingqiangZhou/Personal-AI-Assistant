@echo off
REM Test Authentication Endpoints with curl on Windows

set BASE_URL=http://localhost:8000
set API_V1=/api/v1

echo Testing Authentication Endpoints
echo ================================

REM 1. Health Check
echo.
echo 1. Health Check:
curl -s "%BASE_URL%/health"

REM 2. Register User
echo.
echo 2. Register User:
curl -s -X POST "%BASE_URL%%API_V1%/auth/register" ^
  -H "Content-Type: application/json" ^
  -d "{\"email\": \"test@example.com\", \"password\": \"testpassword123\", \"username\": \"testuser\", \"full_name\": \"Test User\"}"

REM 3. Login
echo.
echo 3. Login:
curl -s -X POST "%BASE_URL%%API_V1%/auth/login" ^
  -H "Content-Type: application/json" ^
  -d "{\"email_or_username\": \"test@example.com\", \"password\": \"testpassword123\"}"

REM For simplicity, we'll use hardcoded tokens for subsequent tests
REM In a real scenario, you would extract tokens from the login response

REM 4. Get Current User Info (with a placeholder token)
echo.
echo 4. Get Current User Info:
curl -s -X GET "%BASE_URL%%API_V1%/auth/me" ^
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"

echo.
echo ================================
echo Authentication Tests Complete!
echo To run the full test with token extraction, run test_auth_endpoints.py
echo ================================