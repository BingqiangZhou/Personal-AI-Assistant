@echo off
echo 正在运行 Flutter Windows 桌面应用...
echo.

cd /d "E:\Projects\AI\PersonalKnowledgeLibrary\Claude\personal-ai-assistant\frontend"

if exist "pubspec.yaml" (
    echo [OK] 在 frontend 目录
    echo 当前目录: %CD%
    echo.
    echo 正在启动应用...
    flutter run -d windows
) else (
    echo [ERROR] 未找到 pubspec.yaml
    echo 请检查当前目录: %CD%
    pause
)

if errorlevel 1 (
    echo.
    echo === 转换为浏览器运行模式 ===
    echo 正在启动 Chrome 版本...
    cd mobile
    flutter run -d chrome
)
