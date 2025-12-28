#!/bin/sh
# Nginx HTTPS Mode Auto-Configuration Script
# This script switches between HTTP and HTTPS configurations based on HTTPS_MODE env var

set -e

echo "=== Nginx Auto-Configuration ==="
echo "HTTPS_MODE: ${HTTPS_MODE:-http}"
echo "DOMAIN: ${DOMAIN:-localhost}"

# Remove default configs to avoid conflicts
rm -f /etc/nginx/conf.d/default.conf
rm -f /etc/nginx/conf.d/default-ssl.conf

# Select configuration based on HTTPS_MODE
if [ "${HTTPS_MODE}" = "https" ]; then
    echo "Using HTTPS configuration..."

    # Verify SSL certificates exist
    if [ ! -f "${SSL_CERT_PATH}" ]; then
        echo "ERROR: SSL certificate not found at ${SSL_CERT_PATH}"
        echo "Please place your SSL certificates in the cert directory:"
        echo "  - fullchain.pem (certificate chain)"
        echo "  - privkey.pem (private key)"
        exit 1
    fi

    if [ ! -f "${SSL_KEY_PATH}" ]; then
        echo "ERROR: SSL private key not found at ${SSL_KEY_PATH}"
        exit 1
    fi

    echo "SSL certificates found:"
    echo "  Certificate: ${SSL_CERT_PATH}"
    echo "  Private Key: ${SSL_KEY_PATH}"

    # Use envsubst to replace variables in HTTPS template
    envsubst '${DOMAIN} ${SSL_CERT_PATH} ${SSL_KEY_PATH}' \
        < /etc/nginx/templates/default-ssl.conf.template \
        > /etc/nginx/conf.d/default.conf

    echo "HTTPS configuration activated for domain: ${DOMAIN}"

else
    echo "Using HTTP configuration..."

    # Use envsubst to replace variables in HTTP template
    envsubst '${DOMAIN}' \
        < /etc/nginx/templates/default.conf.template \
        > /etc/nginx/conf.d/default.conf

    echo "HTTP configuration activated for domain: ${DOMAIN}"
fi

# Test nginx configuration
echo "Testing nginx configuration..."
nginx -t

if [ $? -eq 0 ]; then
    echo "Nginx configuration is valid!"
else
    echo "ERROR: Nginx configuration test failed!"
    exit 1
fi

echo "=== Nginx Auto-Configuration Complete ==="
