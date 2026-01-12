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

# =============================================================================
# Run database migrations before starting the application
# 在启动应用前运行数据库迁移
# Only run if RUN_MIGRATIONS is set to true (default: false to avoid duplicates)
# 只有设置 RUN_MIGRATIONS=true 时才运行（默认 false 避免重复执行）
# =============================================================================
if [ "${RUN_MIGRATIONS:-false}" = "true" ]; then
    echo "🔄 Running database migrations..."
    # Run as app user, passing all environment variables
    # Use env -i to start with clean environment, then export needed variables
    if command -v setpriv >/dev/null 2>&1; then
        # setpriv with environment preserved
        setpriv --reuid=$APP_USER --regid=$APP_USER --init-groups \
            env -i HOME="/home/$APP_USER" PATH="$PATH" DATABASE_URL="$DATABASE_URL" \
            REDIS_URL="$REDIS_URL" CELERY_BROKER_URL="$CELERY_BROKER_URL" \
            CELERY_RESULT_BACKEND="$CELERY_RESULT_BACKEND" TZ="$TZ" \
            sh -c "cd /app && alembic upgrade head" 2>&1 || echo "⚠️  Migration skipped (will use app-level init)"
    else
        # su with environment variables explicitly set
        su -s /bin/bash - "$APP_USER" <<EOF || echo "⚠️  Migration skipped (will use app-level init)"
export HOME="/home/$APP_USER"
export DATABASE_URL="$DATABASE_URL"
export REDIS_URL="$REDIS_URL"
export CELERY_BROKER_URL="$CELERY_BROKER_URL"
export CELERY_RESULT_BACKEND="$CELERY_RESULT_BACKEND"
export TZ="$TZ"
cd /app && alembic upgrade head
EOF
    fi
    echo "✅ Migration check complete"
    echo ""
else
    echo "⏭️  Skipping migrations (RUN_MIGRATIONS not set)"
    echo ""
fi

# Get app user's home directory
APP_HOME=$(getent passwd "$APP_USER" | cut -d: -f6)

# Execute the main command as app user
# Set HOME and other important environment variables
# 使用 setpriv 或 su（不带 login shell）切换用户执行命令
if command -v setpriv >/dev/null 2>&1; then
    # setpriv is cleaner - it doesn't fork a shell
    export HOME="$APP_HOME"
    exec setpriv --reuid=$APP_USER --regid=$APP_USER --init-groups "$@"
else
    # su without - (no login shell) to avoid environment pollution
    # Set HOME environment variable explicitly to avoid PostgreSQL client looking in /root
    exec su -s /bin/bash - "$APP_USER" -c "export HOME=$APP_HOME; exec $*"
fi
