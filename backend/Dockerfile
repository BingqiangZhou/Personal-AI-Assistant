# 使用国内基础镜像
FROM docker.m.daocloud.io/library/python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Note: Python slim image already uses optimal package mirrors

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        curl \
        ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy pyproject.toml first
COPY pyproject.toml ./

# Configure pip to use Chinese mirrors for faster downloads
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple \
    && pip config set global.trusted-host pypi.tuna.tsinghua.edu.cn

# Install uv first (faster than regular pip for Python package management)
RUN pip install --no-cache-dir uv

# Copy application code
COPY . .

# Install dependencies using uv with optimized settings
RUN uv pip install --system -e . \
    --index-url https://pypi.tuna.tsinghua.edu.cn/simple \
    --trusted-host pypi.tuna.tsinghua.edu.cn

# Create directories with proper permissions
RUN mkdir -p uploads logs data storage/podcasts temp/transcription

# Copy entrypoint script (must be done before USER switch)
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create non-root user
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app

# Set entrypoint to fix permissions at runtime (runs as root, then switches to app)
# Entrypoint runs as root to fix permissions, then uses su-exec to run as app user
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Expose port
EXPOSE 8000

# Default command (will be run as app user by entrypoint)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
