# Personal AI Assistant - Backend

Backend API service for the Personal AI Assistant application.

## 📦 Tech Stack

- **Framework**: FastAPI (async Python web framework)
- **Database**: PostgreSQL with SQLAlchemy 2.0 (async ORM)
- **Cache**: Redis (async)
- **Task Queue**: Celery with Redis broker
- **Package Manager**: [uv](https://github.com/astral-sh/uv) (fast Python package installer)
- **Code Quality**: Ruff (fast Python linter & formatter)

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- PostgreSQL
- Redis
- [uv](https://github.com/astral-sh/uv) package manager

### Installation

1. **Install dependencies using uv**:
   ```bash
   # Install uv if you haven't already
   pip install uv
   
   # Install project dependencies
   uv sync
   ```

2. **Set up environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Run database migrations**:
   ```bash
   alembic upgrade head
   ```

4. **Start the development server**:
   ```bash
   uv run gunicorn app.main:app --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000 --reload
   ```
   Note: `gunicorn` requires Linux/WSL. On Windows, use Docker Compose or run inside WSL.

5. **Start Celery worker** (in a separate terminal):
   ```bash
   celery -A app.core.celery_app:celery_app worker --loglevel=info
   ```

6. **Start Celery beat scheduler** (in another terminal):
   ```bash
   celery -A app.core.celery_app:celery_app beat --loglevel=info
   ```

## 📚 Dependency Management

This project uses **uv** for dependency management. All dependencies are defined in `pyproject.toml`.

### Adding Dependencies

```bash
# Add a production dependency
uv add fastapi

# Add a development dependency
uv add --dev pytest

# Add a specific version
uv add "httpx>=0.25.0"
```

### Removing Dependencies

```bash
uv remove package-name
```

### Updating Dependencies

```bash
# Update all dependencies
uv sync --upgrade

# Update a specific package
uv add --upgrade package-name
```

### Regenerating requirements.txt

The `requirements.txt` file is auto-generated from `pyproject.toml` for Docker compatibility:

```bash
# Windows (PowerShell)
.\scripts\update_requirements.ps1

# Linux/macOS
./scripts/update_requirements.sh
```

> **⚠️ Important**: Never edit `requirements.txt` manually. Always use `uv add/remove` and regenerate the file.

## 🧪 Code Quality

### Linting & Formatting

We use **Ruff** for both linting and formatting (replaces black, isort, and flake8):

```bash
# Check for issues
uv run ruff check app/

# Auto-fix issues
uv run ruff check --fix app/

# Format code
uv run ruff format app/

# Check formatting without applying
uv run ruff format --check app/
```

### Type Checking

```bash
uv run mypy app/
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=app --cov-report=html

# Run specific test file
uv run pytest tests/test_example.py
```

## Project Structure

```
backend/
|-- alembic/              # Database migrations
|-- app/
|   |-- api/              # API routes
|   |-- core/             # Core configuration, database, security
|   |-- domains/          # Domain-driven design modules
|   |   |-- ai/           # AI model management
|   |   |-- auth/         # Authentication
|   |   |-- podcast/      # Podcast features
|   |   `-- user/         # User management
|   `-- main.py           # FastAPI application entry point
|-- scripts/              # Utility scripts
|-- tests/                # Test suite
|-- pyproject.toml        # Project dependencies and configuration
`-- requirements.txt      # Auto-generated lock file for Docker
```

## 🐳 Docker Deployment

```bash
# Build the image
docker build -t personal-ai-assistant-backend .

# Run the container
docker run -p 8000:8000 --env-file .env personal-ai-assistant-backend
```

Or use Docker Compose:

```bash
cd ../docker
docker-compose up
```

## 📖 API Documentation

Once the server is running, visit:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🔧 Development Workflow

1. **Create a feature branch**
2. **Make your changes**
3. **Run code quality checks**:
   ```bash
   uv run ruff check --fix app/
   uv run ruff format app/
   uv run mypy app/
   ```
4. **Run tests**:
   ```bash
   uv run pytest
   ```
5. **Commit and push**

## 📝 Environment Variables

See `.env.example` for a complete list of required environment variables.

Key variables:
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `SECRET_KEY`: JWT secret key
- `OPENAI_API_KEY`: OpenAI API key (for AI features)

## 🤝 Contributing

1. Follow the code style enforced by Ruff
2. Write tests for new features
3. Update documentation as needed
4. Use `uv add` for dependency changes

## 📄 License

[Your License Here]
