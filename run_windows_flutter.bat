@echo off
chcp 65001 >nul
echo Personal AI Assistant - Windows 桌面版启动器
echo ======================================================
echo.

cd /d "E:\Projects\AI\PersonalKnowledgeLibrary\Claude\personal-ai-assistant\frontend"

if exist "pubspec.yaml" (
    echo [1/4] 检查 Flutter 环境...
    flutter doctor | findstr /C:"Flutter" /C:"Tool" /C:"Android" /C:"Chrome"
    echo.

    echo [2/4] 检查可用设备...
    flutter devices
    echo.

    echo [3/4] 尝试 Windows 桌面版本...
    echo (可能需要开启开发者模式)
    flutter run -d windows

    if errorlevel 1 (
        echo.
        echo [4/4] Windows 构建失败，切换到浏览器版本...
        echo.
        echo 启动浏览器版本作为替代方案:
        echo.
        cd mobile
        flutter run -d chrome --web-port=8080
    )
) else (
    echo [ERROR] 未找到 pubspec.yaml
    echo 请确保在 frontend 目录中运行此脚本
    echo 当前目录: %CD%
    pause
)

echo.
echo ======================================================
echo 如果成功，您应该能看到 Personal AI Assistant 界面
echo.
echo 如果需要帮助，请查看 WINDOWS_INSTRUCTIONS.md 文件
pause