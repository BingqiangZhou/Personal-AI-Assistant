@echo off
REM Comprehensive Flutter Test Runner for Windows
REM Runs all created tests to validate the mobile application

echo ================================================
echo Flutter Mobile App - Comprehensive Test Suite
echo ================================================
echo.

setlocal enabledelayedexpansion

REM Colors (Windows doesn't support ANSI colors in cmd by default, so skip colors)
set GREEN=
set RED=
set NC=

REM Check if Flutter is available
where flutter >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: Flutter is not installed or not in PATH
    exit /b 1
)

echo 1. Flutter Doctor Check
echo ----------------------
flutter doctor
echo.

echo 2. Analyze Project
echo ------------------
cd /d "%~dp0.."
flutter analyze

echo.
echo 3. Run Unit Tests
echo ------------------
echo Running authentication service tests...
flutter test test/services/auth_service_test.dart

echo.
echo Running assistant service tests...
flutter test test/services/assistant_service_test.dart

echo.
echo Running knowledge service tests...
flutter test test/services/knowledge_service_test.dart

echo.
echo Running podcast service tests...
flutter test test/services/podcast_service_test.dart

echo.
echo Running provider tests...
flutter test test/providers/auth_provider_test.dart

echo.
echo Running router tests...
flutter test test/routers/router_test.dart

echo.
echo 4. Run Integration Tests
echo ------------------------
echo Running API integration tests...
flutter test test/integration/api_integration_test.dart

echo.
echo Running user flow tests...
flutter test test/integration/user_flow_test.dart

echo.
echo Running complete widget test...
flutter test test/widget_test.dart

echo.
echo 5. Generate Coverage Report
echo ---------------------------
flutter test --coverage

echo.
echo =================================================
echo All tests completed!
echo =================================================
echo.
echo To generate detailed HTML coverage report:
echo 1. Install genhtml (part of lcov package)
echo 2. Run: genhtml coverage/lcov.info -o coverage/html
echo 3. Open coverage/html/index.html in your browser
echo.
pause
