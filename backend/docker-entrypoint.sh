#!/bin/bash
# =============================================================================
# Docker Entrypoint Script
# =============================================================================
# This script ensures proper permissions for mounted volumes at runtime
# 确保运行时挂载卷的权限正确

set -e

APP_USER=${APP_USER:-app}

echo "🔧 Fixing permissions for mounted volumes..."
echo "   User: $APP_USER"

# Fix permissions for directories that may be mounted from host
# 修复可能从宿主机挂载的目录权限
DIRECTORIES_TO_FIX=(
    "/app/temp/transcription"
    "/app/storage/podcasts"
    "/app/uploads"
    "/app/logs"
    "/app/data"
)

for dir in "${DIRECTORIES_TO_FIX[@]}"; do
    if [ -d "$dir" ]; then
        # Check if directory is owned by root (which happens with volume mounts)
        current_owner=$(stat -c '%u' "$dir" 2>/dev/null || echo "0")
        if [ "$current_owner" = "0" ]; then
            echo "   📁 Fixing ownership: $dir"
            chown -R $APP_USER:$APP_USER "$dir" 2>/dev/null || true
            chmod -R 775 "$dir" 2>/dev/null || true
        fi
    else
        # Create directory if it doesn't exist
        echo "   📁 Creating: $dir"
        mkdir -p "$dir" 2>/dev/null || true
        chown -R $APP_USER:$APP_USER "$dir" 2>/dev/null || true
        chmod -R 775 "$dir" 2>/dev/null || true
    fi
done

echo "✅ Permission setup complete"
echo ""

# Execute the main command as app user using su
# 使用 su 切换到 app 用户执行命令
# exec su - "$APP_USER" -c "$*"  # This doesn't work well with complex commands
# Instead, pass the command directly to su using --
exec su - "$APP_USER" -- "$@"
