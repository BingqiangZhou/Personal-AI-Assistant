# 🔐 密码设置和管理指南

## 📋 目录
1. [创建初始管理员账号](#1-创建初始管理员账号)
2. [用户注册（API方式）](#2-用户注册api方式)
3. [密码重置流程](#3-密码重置流程)
4. [管理员重置用户密码](#4-管理员重置用户密码)
5. [密码安全要求](#5-密码安全要求)
6. [常见问题](#6-常见问题)

---

## 1. 创建初始管理员账号

### 方法一：使用首次运行设置页面（推荐）

**步骤**：

1. 启动后端服务：
```bash
cd docker
docker compose up -d
```

2. 访问首次运行设置页面：
```
http://localhost:8000/super/setup
```

3. 填写管理员信息：
   - 管理员用户名（必填）
   - 管理员邮箱（必填）
   - 显示名称（可选）
   - 密码（必填，至少8个字符）
   - 确认密码（必填）

4. 点击"创建管理员账号并开始使用"按钮

5. **设置双因素认证（强制）**
   - 创建成功后会自动跳转到 2FA 设置页面
   - 使用 Authenticator App 扫描二维码
   - 输入验证码完成设置
   - 完成后才能进入管理后台

6. 进入管理后台

**特点**：
- ✅ 图形化界面，操作简单
- ✅ 自动验证密码强度和一致性
- ✅ 创建成功后自动跳转到 2FA 设置
- ✅ 强制启用 2FA，提高账号安全性
- ✅ 如果已存在管理员，会自动跳转到登录页面
- ✅ 使用 CSRF 保护，安全可靠

### 方法二：直接操作数据库

```bash
# 进入PostgreSQL容器
docker compose exec postgres psql -U admin -d personal_ai

# 插入管理员用户（密码需要先hash）
INSERT INTO users (
    username, email, hashed_password,
    account_name, status, is_superuser, is_verified,
    created_at, updated_at
) VALUES (
    'admin',
    'admin@example.com',
    '$2b$12$...',  -- 使用bcrypt hash的密码
    'Administrator',
    'active',
    true,
    true,
    NOW(),
    NOW()
);
```

**生成密码hash**：
```python
# 在Python中生成密码hash
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
hashed = pwd_context.hash("your_password")
print(hashed)
```

---

## 2. 用户注册（API方式）

### 通过API注册新用户

**端点**：`POST /api/v1/auth/register`

**请求示例**：
```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "username": "newuser",
    "remember_me": false
  }'
```

**响应示例**：
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

**注意**：
- 注册成功后自动登录，返回访问令牌
- 新注册用户默认不是超级用户（`is_superuser=False`）
- 需要管理员手动提升权限才能访问管理后台

---

## 3. 密码重置流程

### 步骤1：请求密码重置

**端点**：`POST /api/v1/auth/forgot-password`

**请求示例**：
```bash
curl -X POST http://localhost:8000/api/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

**响应示例**：
```json
{
  "message": "Password reset instructions sent to email",
  "token": "abc123...",  // 仅开发环境返回
  "expires_at": "2026-01-11T21:00:00"
}
```

**注意**：
- 生产环境会发送邮件，开发环境直接返回token
- Token有效��：1小时
- 即使邮箱不存在也返回成功（防止邮箱枚举攻击）

### 步骤2：使用Token重置密码

**端点**：`POST /api/v1/auth/reset-password`

**请求示例**：
```bash
curl -X POST http://localhost:8000/api/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "abc123...",
    "new_password": "NewSecurePassword123!"
  }'
```

**响应示例**：
```json
{
  "message": "Password reset successfully"
}
```

---

## 4. 管理员重置用户密码

### 通过管理后台重置

**步骤**：

1. 登录管理后台：`http://localhost:8000/super/login`

2. 访问用户管理页面：`http://localhost:8000/super/users`

3. 找到目标用户，点击"重置密码"按钮

4. 系统生成随机强密码并显示：
```
Password reset successful. New password: Xy9kL2mN4pQ7rS8t
```

5. **立即复制密码**（仅显示一次）

6. 将新密码告知用户

**API方式**：
```bash
# 需要管理员会话cookie
curl -X PUT http://localhost:8000/super/users/2/reset-password \
  -H "Cookie: admin_session=..." \
  -H "Content-Type: application/json"
```

**特点**：
- 生成16字符随机密码（URL安全字符）
- 密码仅显示一次
- 操作记录到审计日志
- 用户下次登录时应修改密码

---

## 5. 密码安全要求

### 密码强度建议

**最低要求**：
- 长度：至少8个字符
- 复杂度：建议包含大小写字母、数字和特殊字符

**推荐密码**：
- 长度：12-16个字符
- 包含：大写字母、小写字母、数字、特殊字符
- 示例：`MyP@ssw0rd2026!`

### 密码存储

**技术细节**：
- 算法：bcrypt
- 工作因子：12（默认）
- 不存储明文密码
- 每个密码使用唯一的salt

**示例hash**：
```
$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYqKqZ.Oe6u
```

### 密码策略

**建议配置**：
- 密码有效期：90天（可选）
- 密码历史：不能重复使用最近5个密码（可选）
- 登录失败锁定：5次失败后锁定账号（可选）
- 会话超时：30分钟无活动自动登出

---

## 6. 常见问题

### Q1: 忘记管理员密码怎么办？

**方案1：使用密码重置API**
```bash
# 1. 请求重置
curl -X POST http://localhost:8000/api/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com"}'

# 2. 使用返回的token重置密码
curl -X POST http://localhost:8000/api/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "返回的token",
    "new_password": "NewPassword123!"
  }'
```

**方案2：直接修改数据库**
```bash
# 进入容器
docker compose exec backend python

# 在Python中生成新密码hash
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
new_hash = pwd_context.hash("NewPassword123!")
print(new_hash)

# 退出Python，进入数据库
docker compose exec postgres psql -U admin -d personal_ai

# 更新密码
UPDATE users
SET hashed_password = '$2b$12$...'  -- 使用上面生成的hash
WHERE username = 'admin';
```

### Q2: 如何修改现有用户的密码？

**管理员操作**：
1. 登录管理后台
2. 访问用户管理页面
3. 点击"重置密码"
4. 复制生成的新密码
5. 告知用户新密码

**用户自己修改**：
- 目前需要通过API实现
- 或使用密码重置流程

### Q3: 如何提升普通用户为管理员？

**方法1：通过数据库**
```sql
UPDATE users
SET is_superuser = true
WHERE username = 'username';
```

**方法2：通过Python脚本**
```python
# 在Docker容器中
docker compose exec backend python

from sqlalchemy import select
from app.core.database import async_session_maker
from app.domains.user.models import User
import asyncio

async def make_superuser(username):
    async with async_session_maker() as db:
        result = await db.execute(
            select(User).where(User.username == username)
        )
        user = result.scalar_one_or_none()
        if user:
            user.is_superuser = True
            await db.commit()
            print(f"User {username} is now a superuser")
        else:
            print(f"User {username} not found")

asyncio.run(make_superuser('username'))
```

### Q4: 密码重置token在哪里查看？

**开发环境**：
- Token直接在API响应中返回
- 也可以查询数据库：
```sql
SELECT token, expires_at, is_used
FROM password_resets
WHERE email = 'user@example.com'
ORDER BY created_at DESC
LIMIT 1;
```

**生产环境**：
- Token通过邮件发送
- 不在API响应中返回（安全考虑）

### Q5: 如何批量创建用户？

**创建批量导入脚本**：
```python
# app/scripts/bulk_create_users.py
import asyncio
import csv
from app.core.database import async_session_maker
from app.core.security import get_password_hash
from app.domains.user.models import User, UserStatus

async def bulk_create_users(csv_file):
    async with async_session_maker() as db:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                user = User(
                    username=row['username'],
                    email=row['email'],
                    hashed_password=get_password_hash(row['password']),
                    account_name=row.get('account_name', row['username']),
                    status=UserStatus.ACTIVE,
                    is_superuser=row.get('is_superuser', 'false').lower() == 'true',
                    is_verified=True,
                )
                db.add(user)
            await db.commit()
            print(f"Created {len(list(reader))} users")

# 使用方法
# asyncio.run(bulk_create_users('users.csv'))
```

**CSV格式**：
```csv
username,email,password,account_name,is_superuser
user1,user1@example.com,Password123!,User One,false
user2,user2@example.com,Password456!,User Two,false
admin2,admin2@example.com,AdminPass789!,Admin Two,true
```

### Q6: 2FA启用后忘记Authenticator App怎么办？

**解决方案**：
```sql
-- 禁用用户的2FA
UPDATE users
SET is_2fa_enabled = false,
    totp_secret = NULL
WHERE username = 'username';
```

然后用户可以重新登录并设置新的2FA。

---

## 📝 快速参考

### 创建管理员
访问首次运行设置页面：
```
http://localhost:8000/super/setup
```
或者使用数据库方式（见上文"方法二：直接操作数据库"）

### 重置管理员密码（数据库方式）
```bash
# 1. 生成密码hash
docker compose exec backend python -c "from passlib.context import CryptContext; print(CryptContext(schemes=['bcrypt']).hash('NewPassword123!'))"

# 2. 更新数据库
docker compose exec postgres psql -U admin -d personal_ai -c "UPDATE users SET hashed_password = '\$2b\$12\$...' WHERE username = 'admin';"
```

### 提升用户为管理员
```bash
docker compose exec postgres psql -U admin -d personal_ai -c "UPDATE users SET is_superuser = true WHERE username = 'username';"
```

### 禁用2FA
```bash
docker compose exec postgres psql -U admin -d personal_ai -c "UPDATE users SET is_2fa_enabled = false, totp_secret = NULL WHERE username = 'username';"
```

---

## 🔒 安全最佳实践

1. **初始设置**
   - 立即修改默认管理员密码
   - 启用2FA保护管理员账号
   - 使用强密码（12+字符）

2. **日常管理**
   - 定期审查用户权限
   - 监控审计日志
   - 及时禁用离职用户账号

3. **密码管理**
   - 不要在代码中硬编码密码
   - 使用环境变量存储敏感信息
   - 定期更新密码

4. **访问控制**
   - 最小权限原则
   - 仅授予必要的超级用户权限
   - 使用2FA保护关键账号

---

**最后更新**: 2026-01-11
**版本**: 1.0.0
