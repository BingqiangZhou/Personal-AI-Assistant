# 开发者快速参

## 🔧 常用命令

### 依赖管理
```bash
# 添加生产依赖
uv add package-name

# 添加开发依
uv add --dev package-name

# 移除依赖
uv remove package-name

# 同步所有依
uv sync

# 更新依赖
uv sync --upgrade
```

### 代码质量
```bash
# 检查代码问
uv run ruff check app/

# 自动修复问题
uv run ruff check --fix app/

# 格式化代
uv run ruff format app/

# 检查格式（不修改）
uv run ruff format --check app/

# 类型检
uv run mypy app/
```

### 测试
```bash
# 运行所有测
uv run pytest

# 带覆盖率
uv run pytest --cov=app

# 运行特定测试
uv run pytest tests/test_example.py -v
```

### 数据
```bash
# 创建迁移
alembic revision --autogenerate -m "description"

# 应用迁移
alembic upgrade head

# 回滚
alembic downgrade -1
```

### 服务启动
```bash
# API 服务
uv run gunicorn app.main:app --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000 --reload

# Note: gunicorn requires Linux/WSL (fcntl). On native Windows, use Docker Compose or WSL.

# Celery Worker
celery -A app.core.celery_app:celery_app worker --loglevel=info

# Celery Beat
celery -A app.core.celery_app:celery_app beat --loglevel=info
```

## 📝 提交前检查清

- [ ] 运行 `uv run ruff check --fix app/`
- [ ] 运行 `uv run ruff format app/`
- [ ] 运行 `uv run pytest`
- [ ] 如果修改了依赖，运行 `.\scripts\update_requirements.ps1`
- [ ] 检git 状态，确保只提交需要的文件

## 🚨 重要提醒

**不要这样*:
- 手动编辑 `requirements.txt`
- 使用 `pip install` 直接安装包（应该`uv add`
- 跳过代码格式化直接提

**应该这样*:
- 使用 `uv add/remove` 管理依赖
- 提交前运ruff 检查和格式
- 编写测试并确保通过
