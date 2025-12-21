@echo off
echo ===========================================
echo Personal AI Assistant - 播客转录功能启动脚本
echo ===========================================
echo.

echo 检查环境配置...
if not exist "..\backend\.env" (
    echo [错误] 未找到环境配置文件 backend\.env
    echo 请先复制 backend\.env.example 到 backend\.env 并配置转录API密钥
    pause
    exit /b 1
)

echo 检查转录API密钥配置...
findstr /C:"your_siliconflow_api_key_here" "..\backend\.env" >nul
if %errorlevel%==0 (
    echo [警告] 转录API密钥尚未配置
    echo 请编辑 backend\.env 文件，设置 TRANSCRIPTION_API_KEY
    echo.
    set /p continue="是否继续启动？(y/N): "
    if /i not "%continue%"=="y" exit /b 1
)

echo 创建必要的目录...
if not exist "..\backend\storage\podcasts" mkdir "..\backend\storage\podcasts"
if not exist "..\backend\temp\transcription" mkdir "..\backend\temp\transcription"

echo.
echo 启动Docker服务...
docker-compose -f docker-compose.podcast.yml up -d

if %errorlevel%==0 (
    echo.
    echo ✅ 服务启动成功！
    echo.
    echo 📋 服务信息:
    echo    - 后端API: http://localhost:8000
    echo    - API文档: http://localhost:8000/docs
    echo    - 数据库: localhost:5432
    echo    - Redis: localhost:6379
    echo.
    echo 🔍 查看日志: docker-compose -f docker-compose.podcast.yml logs -f backend
    echo 🛑 停止服务: docker-compose -f docker-compose.podcast.yml down
) else (
    echo.
    echo ❌ 服务启动失败，请检查Docker是否正常运行
    pause
    exit /b 1
)

echo.
echo 按任意键退出...
pause >nul