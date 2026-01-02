#!/bin/bash
# =============================================================================
# Playwright Installation Verification Script
# =============================================================================

set -e

echo "🔍 Verifying Playwright Installation..."
echo ""

# Check if playwright command exists
if ! command -v playwright &> /dev/null; then
    echo "❌ Playwright command not found"
    echo "   Installing Playwright..."
    playwright install --help
fi

echo "✅ Playwright command found"
echo ""

# Check Chromium installation
echo "🔍 Checking Chromium browser installation..."
if python -c "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); browser = p.chromium.launch(); browser.close(); p.stop(); print('Chromium is installed')" 2>/dev/null; then
    echo "✅ Chromium browser is installed and working"
else
    echo "❌ Chromium browser test failed"
    echo "   Installing Chromium..."
    playwright install chromium
    playwright install-deps chromium
fi

echo ""

# Check system dependencies
echo "🔍 Checking system dependencies..."
REQUIRED_LIBS=(
    "libnss3"
    "libnspr4"
    "libatk1.0-0"
    "libatk-bridge2.0-0"
    "libcups2"
    "libdrm2"
    "libdbus-1-3"
    "libxkbcommon0"
    "libxcomposite1"
    "libxdamage1"
    "libxfixes3"
    "libxrandr2"
    "libgbm1"
    "libasound2"
)

MISSING_LIBS=()
for lib in "${REQUIRED_LIBS[@]}"; do
    if dpkg -l | grep -q "^ii  $lib"; then
        echo "  ✅ $lib"
    else
        echo "  ❌ $lib (missing)"
        MISSING_LIBS+=("$lib")
    fi
done

if [ ${#MISSING_LIBS[@]} -gt 0 ]; then
    echo ""
    echo "⚠️  Missing system dependencies detected"
    echo "   Run: apt-get update && apt-get install -y ${MISSING_LIBS[*]}"
else
    echo ""
    echo "✅ All system dependencies are installed"
fi

echo ""

# Check Playwright Python package
echo "🔍 Checking Playwright Python package..."
if python -c "import playwright; print(f'Playwright version: {playwright.__version__}')" 2>/dev/null; then
    echo "✅ Playwright Python package is installed"
else
    echo "❌ Playwright Python package not found"
    echo "   Run: pip install playwright"
fi

echo ""

# Check shared memory
echo "🔍 Checking shared memory..."
SHM_SIZE=$(df -h /dev/shm | tail -1 | awk '{print $2}')
echo "   Shared memory size: $SHM_SIZE"
SHM_SIZE_MB=$(df -m /dev/shm | tail -1 | awk '{print $2}')
if [ "$SHM_SIZE_MB" -lt 1024 ]; then
    echo "⚠️  Shared memory is less than 1GB (recommended: 2GB)"
    echo "   Add to docker-compose.yml: shm_size: 2gb"
else
    echo "✅ Shared memory size is sufficient"
fi

echo ""
echo "=========================================="
echo "✅ Playwright verification complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Start the Docker containers: docker-compose up -d"
echo "2. Check logs: docker-compose logs -f backend celery_worker"
echo "3. Test browser download: Trigger a podcast transcription task"
echo ""
