@echo off
chcp 65001 >nul
echo ======================================================
echo     个人AI助手 - 播客功能一键启动脚本
echo ======================================================
echo.

echo [1/5] 检查Docker环境...
docker --version >nul 2>&1
if %errorlevel% NEQ 0 (
    echo ❌ 错误: 未找到Docker，请安装Docker Desktop
    echo 下载地址: https://www.docker.com/products/docker-desktop/
    pause
    exit /b 1
)
echo ✅ Docker 已安装

docker compose version >nul 2>&1
if %errorlevel% NEQ 0 (
    echo  ⚠️  警告: Docker compose 未找到，尝试使用旧版命令...
    set COMPOSE_CMD=docker-compose
) else (
    set COMPOSE_CMD=docker compose
)
echo ✅ Docker compose 可用

echo [2/5] 检查配置文件...
if not exist "backend\.env" (
    echo  ⚠️  未找到 .env 文件，创建默认配置...
    copy backend\.env.example backend\.env
    echo 请编辑 backend\.env 文件配置以下关键参数:
    echo   - SECRET_KEY: 使用 python -c "import secrets; print(secrets.token_urlsafe(48))" 生成
    echo   - 检查所有密码是否足够安全
    echo.
    notepad backend\.env
)
echo ✅ 配置文件检查完成

echo [3/5] 开始构建和启动服务...
echo 这可能需要几分钟 (首次运行会下载镜像)
echo.

%COMPOSE_CMD% -f docker-compose.podcast.yml up -d --build

if %errorlevel% NEQ 0 (
    echo ❌ 启动失败，请检查错误信息
    echo.
    echo 尝试显示最后20行日志:
    %COMPOSE_CMD% -f docker-compose.podcast.yml logs --tail=20
    pause
    exit /b 1
)

echo.
echo [4/5] 等待服务就绪...
timeout /t 10 /nobreak >nul

echo [5/5] 检查服务状态...
%COMPOSE_CMD% -f docker-compose.podcast.yml ps

echo.
echo ======================================================
echo              ✅ 部署启动完成！
echo ======================================================
echo.
echo 服务访问信息:
echo   API文档: http://localhost:8000/docs
echo   健康检查: http://localhost:8000/health
echo.
echo 重要提示:
echo   1. 首次启动需要1-3分钟 (数据库初始化)
echo   2. 所有服务状态应显示"Up"或"Running"
echo   3. 如果失败，运行: docker compose -f docker-compose.podcast.yml logs backend
echo.
echo 操作命令:
echo   停止服务: docker compose -f docker-compose.podcast.yml down
echo   查看日志: docker compose -f docker-compose.podcast.yml logs -f backend
echo   重启服务: docker compose -f docker-compose.podcast.yml restart
echo.
echo 完成后请按任意键退出...
pause >nul
