#!/bin/sh
# Nginx 自动配置脚本 / Nginx Auto-Configuration Script
# 根据是否有 SSL 证书自动选择 HTTP 或 HTTPS 配置
# Automatically selects HTTP or HTTPS config based on SSL certificate availability

set -e

echo "=== Nginx Auto-Configuration ==="

# 清理镜像自带的默认配置文件，避免冲突
# Clean up default config files from the base image to avoid conflicts
echo "🧹 Cleaning up default configurations..."
if [ -f "/etc/nginx/conf.d/default.conf" ]; then
    rm -f /etc/nginx/conf.d/default.conf
    echo "  ✓ Removed: /etc/nginx/conf.d/default.conf"
fi

# 获取环境变量 / Get environment variables
DOMAIN="${DOMAIN:-localhost}"
SSL_CERT_PATH="${SSL_CERT_PATH:-/etc/nginx/cert/fullchain.pem}"
SSL_KEY_PATH="${SSL_KEY_PATH:-/etc/nginx/cert/privkey.pem}"

echo "Domain: ${DOMAIN}"
echo "SSL Certificate: ${SSL_CERT_PATH}"

# 检查 SSL 证书是否存在 / Check if SSL certificate exists
if [ -f "${SSL_CERT_PATH}" ] && [ -f "${SSL_KEY_PATH}" ]; then
    echo "✅ SSL certificates found - enabling HTTPS mode"

    # 禁用 HTTP 模板 / Disable HTTP template
    if [ -f "/etc/nginx/templates/default.conf.template" ]; then
        mv "/etc/nginx/templates/default.conf.template" \
           "/etc/nginx/templates/default.conf.template.disabled" 2>/dev/null || true
        echo "  - Disabled HTTP template"
    fi

    # 启用 HTTPS 模板 / Enable HTTPS template
    if [ -f "/etc/nginx/templates/default-ssl.conf.template.available" ]; then
        mv "/etc/nginx/templates/default-ssl.conf.template.available" \
           "/etc/nginx/templates/default-ssl.conf.template"
        echo "  - Enabled HTTPS template (HTTP + HTTPS)"
    fi

    # 检查证书有效性 / Verify certificate validity
    if openssl x509 -in "${SSL_CERT_PATH}" -noout -checkend 0 2>/dev/null; then
        echo "  - SSL certificate is valid"
    else
        echo "  ⚠️  Warning: SSL certificate may be invalid or expired"
    fi

else
    echo "ℹ️  No SSL certificates found - using HTTP only mode"

    # 禁用 HTTPS 模板 / Disable HTTPS template
    if [ -f "/etc/nginx/templates/default-ssl.conf.template" ]; then
        mv "/etc/nginx/templates/default-ssl.conf.template" \
           "/etc/nginx/templates/default-ssl.conf.template.available" 2>/dev/null || true
        echo "  - Disabled HTTPS template"
    fi

    # 启用 HTTP 模板 / Enable HTTP template
    if [ -f "/etc/nginx/templates/default.conf.template.disabled" ]; then
        mv "/etc/nginx/templates/default.conf.template.disabled" \
           "/etc/nginx/templates/default.conf.template"
        echo "  - Enabled HTTP template"
    fi

    # 确保至少有一个模板可用 / Ensure at least one template is available
    if [ ! -f "/etc/nginx/templates/default.conf.template" ]; then
        echo "  ❌ Error: No HTTP template available!"
        exit 1
    fi
fi

# 列出当前激活的模板 / List active templates
echo ""
echo "Active templates:"
ls -la /etc/nginx/templates/*.template 2>/dev/null | awk '{print "  " $NF}' || echo "  (none found)"

echo ""
echo "=== Configuration complete, starting Nginx ==="
