# 管理后台使用指南

## 功能概述

管理后台提供了以下功能:

1. **API Key管理**: 创建、查看、启用/禁用、删除API密钥
2. **RSS订阅管理**: 查看、编辑、删除、手动刷新RSS订阅
3. **安全认证**: 基于Session的登录认证系统

## 技术栈

- **后端**: FastAPI + Jinja2
- **前端**: htmx + Tailwind CSS + Alpine.js
- **认证**: Session-based authentication with secure cookies
- **数据库**: PostgreSQL

## 访问管理后台

### 1. 启动后端服务

```bash
cd docker
docker-compose up -d
```

### 2. 运行数据库迁移

```bash
cd backend
uv run alembic upgrade head
```

### 3. 访问管理后台

打开浏览器访问: `http://localhost:8000/admin/login`

### 4. 登录

使用现有的用户账号登录。如果没有账号,需要先通过API注册:

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@example.com",
    "password": "your_password"
  }'
```

## 功能使用

### API Key管理

1. **创建API Key**
   - 点击"创建API Key"按钮
   - 填写名称和描述
   - 系统会生成一个以`pak_`开头的API Key
   - **重要**: 创建后立即复制保存,之后无法再次查看明文

2. **启用/禁用API Key**
   - 点击表格中的"启用"或"禁用"按钮
   - 禁用的Key无法用于API访问

3. **删除API Key**
   - 点击"删除"按钮
   - 确认后永久删除

### RSS订阅管理

1. **查看订阅列表**
   - 显示所有RSS订阅及其状态
   - 包括标题、URL、最后更新时间等信息

2. **编辑订阅**
   - 点击"编辑"按钮
   - 修改标题或Feed URL
   - 保存更改

3. **手动刷新订阅**
   - 点击"刷新"按钮
   - 触发立即更新订阅内容

4. **删除订阅**
   - 点击"删除"按钮
   - 确认后永久删除

## 安全特性

1. **Session认证**: 使用安全的Session cookie进行认证
2. **会话超时**: 30分钟无操作自动登出
3. **密码加密**: 使用bcrypt加密存储
4. **HTTPS**: 生产环境强制使用HTTPS
5. **CSRF保护**: 防止跨站请求伪造攻击(TODO)
6. **审计日志**: 记录所有管理操作

## 开发说明

### 目录结构

```
backend/app/admin/
├── __init__.py
├── dependencies.py      # 认证依赖
├── models.py           # API Key数据模型
├── router.py           # 路由处理
├── schemas.py          # 表单验证
├── templates/          # Jinja2模板
│   ├── base.html       # 基础模板
│   ├── login.html      # 登录页
│   ├── dashboard.html  # 管理首页
│   ├── apikeys.html    # API Key管理
│   └── subscriptions.html # RSS订阅管理
└── static/             # 静态文件(预留)
```

### 添加新功能

1. 在`router.py`中添加新路由
2. 创建对应的Jinja2模板
3. 使用htmx实现无刷新交互
4. 添加认证依赖`admin_required`

### 数据库迁移

```bash
# 创建新迁移
cd backend
uv run alembic revision --autogenerate -m "description"

# 应用迁移
uv run alembic upgrade head

# 回滚迁移
uv run alembic downgrade -1
```

## 故障排查

### 无法登录

1. 检查用户是否存在且激活
2. 检查密码是否正确
3. 查看后端日志: `docker-compose logs -f backend`

### 页面无法加载

1. 检查后端服务是否运行: `docker-compose ps`
2. 检查数据库连接: `docker-compose logs postgres`
3. 检查模板文件是否存在

### htmx交互失败

1. 打开浏览器开发者工具查看网络请求
2. 检查后端日志中的错误信息
3. 确认路由路径是否正确

## TODO

- [ ] 添加CSRF保护
- [ ] 实现API Key使用统计
- [ ] 添加用户管理功能
- [ ] 实现权限角色系统
- [ ] 添加操作审计日志查看
- [ ] 实现RSS订阅批量操作
- [ ] 添加系统监控面板

## 相关文档

- [FastAPI文档](https://fastapi.tiangolo.com/)
- [htmx文档](https://htmx.org/)
- [Jinja2文档](https://jinja.palletsprojects.com/)
- [Tailwind CSS文档](https://tailwindcss.com/)
