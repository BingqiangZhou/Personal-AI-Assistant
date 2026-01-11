# 首次运行设置指南

## 📋 概述

Personal AI Assistant 提供了一个友好的首次运行设置页面，用于创建初始管理员账号。当系统检测到没有管理员用户时，会自动引导您完成设置。

## 🚀 快速开始

### 1. 启动服务

```bash
cd docker
docker compose up -d
```

### 2. 访问设置页面

打开浏览器访问：
```
http://localhost:8000/super/setup
```

### 3. 填写管理员信息

在设置页面填写以下信息：

- **管理员用户名**（必填）
  - 建议使用 `admin` 或您的名字
  - 示例：`admin`

- **管理员邮箱**（必填）
  - 用于登录和密码重置
  - 示例：`admin@example.com`

- **显示名称**（可选）
  - 在界面上显示的名称
  - 示例：`系统管理员`

- **密码**（必填）
  - 至少8个字符
  - 建议使用大小写字母、数字和特殊字符组合
  - 示例：`MyP@ssw0rd2026!`

- **确认密码**（必填）
  - 必须与密码一致

### 4. 创建账号

点击"创建管理员账号并开始使用"按钮。

### 5. 设置双因素认证（2FA）

创建成功后，系统会自动跳转到 2FA 设置页面：

**步骤 1：扫描二维码**
- 使用 Authenticator App（如 Google Authenticator、Microsoft Authenticator）扫描页面上的二维码
- 或者手动输入显示的密钥

**步骤 2：验证设置**
- 在 Authenticator App 中查看生成的 6 位数字验证码
- 在页面上输入验证码
- 点击"验证并启用"按钮

**注意**：
- ⚠️ 首次设置必须完成 2FA 配置才能进入管理后台
- ⚠️ 请妥善保存 Authenticator App，丢失后需要通过数据库重置
- ✅ 推荐使用支持云备份的 Authenticator App（如 Authy、1Password）

### 6. 进入管理后台

2FA 验证成功后，系统会自动跳转到管理后台：
```
http://localhost:8000/super
```

## 🔒 安全特性

### CSRF 保护
- 所有表单提交都使用 CSRF token 保护
- 防止跨站请求伪造攻击

### 密码加密
- 使用 bcrypt 算法加密存储
- 工作因子：12
- 不存储明文密码

### 自动验证
- 客户端和服务端双重验证
- 密码长度检查（至少8个字符）
- 密码一致性检查
- 用户名和邮箱唯一性检查

### 会话管理
- 创建成功后自动创建安全会话
- 会话有效期：30分钟
- 使用 HttpOnly Cookie 存储

## 🔄 工作流程

```
用户访问 /super/* 路径
    ↓
first_run_middleware 检查是否存在管理员
    ↓
如果不存在管理员 → 重定向到 /super/setup
    ↓
用户填写表单并提交
    ↓
验证输入（密码长度、一致性、唯一性）
    ↓
创建管理员用户（is_superuser=True）
    ↓
生成 TOTP 密钥并保存到用户记录
    ↓
创建会话并重定向到 /super/2fa/setup
    ↓
显示二维码和密钥
    ↓
用户扫描二维码并输入验证码
    ↓
验证 TOTP 令牌
    ↓
启用 2FA（is_2fa_enabled=True）
    ↓
跳转到管理后台 /super
```

## ⚠️ 注意事项

### 1. 只能创建一次
- 如果已存在管理员用户，访问 `/super/setup` 会自动跳转到登录页面
- 这是为了防止未授权创建额外的管理员账号

### 2. 密码要求
- 最低长度：8个字符
- 建议长度：12-16个字符
- 建议包含：大小写字母、数字、特殊字符

### 3. 首次登录后
- ⚠️ **必须完成 2FA 设置才能进入管理后台**
- 系统会自动跳转到 2FA 设置页面
- 使用 Authenticator App 扫描二维码
- 输入验证码完成设置
- 建议使用支持云备份的 Authenticator App（如 Authy、1Password）

### 4. 2FA 密钥管理
- 妥善保存 Authenticator App
- 如果丢失，需要通过数据库重置：
  ```sql
  UPDATE users SET is_2fa_enabled = false, totp_secret = NULL WHERE username = 'admin';
  ```
- 建议截图保存二维码或手动输入的密钥作为备份

### 5. 密码管理
- 不要使用弱密码（如：123456、password）
- 不要在多个系统使用相同密码
- 定期更换密码（建议90天）
- 使用密码管理器存储密码

## 🛠️ 故障排除

### 问题1：无法访问设置页面

**症状**：访问 `/super/setup` 返回 404

**解决方案**：
1. 检查后端服务是否正常运行：
   ```bash
   docker compose ps
   docker compose logs backend
   ```

2. 检查路由是否正确注册：
   ```bash
   curl http://localhost:8000/health
   ```

### 问题2：提交表单后报错

**症状**：提交表单后显示错误消息

**可能原因**：
- 密码长度不足（少于8个字符）
- 两次输入的密码不一致
- 用户名或邮箱已存在
- CSRF token 验证失败

**解决方案**：
1. 检查密码是否符合要求
2. 确保两次输入的密码完全一致
3. 使用不同的用户名和邮箱
4. 刷新页面重新获取 CSRF token

### 问题3：创建成功但 2FA 设置失败

**症状**：管理员创建成功，但 2FA 设置页面报错或无法验证

**解决方案**：
1. 检查 TOTP 密钥是否正确生成：
   ```bash
   docker compose exec postgres psql -U admin -d personal_ai -c "SELECT id, username, totp_secret, is_2fa_enabled FROM users WHERE username = 'admin';"
   ```

2. 确保 Authenticator App 的时间同步正确
   - 大多数 Authenticator App 依赖设备时间
   - 确保设备时间与服务器时间一致

3. 如果验证码一直错误，重新生成 TOTP 密钥：
   ```bash
   docker compose exec postgres psql -U admin -d personal_ai -c "UPDATE users SET totp_secret = NULL WHERE username = 'admin';"
   ```
   然后重新访问 `/super/2fa/setup`

### 问题4：丢失 Authenticator App 无法登录

**症状**：手机丢失或 Authenticator App 被删除，无法完成 2FA 验证

**解决方案**：
通过数据库禁用 2FA：
```bash
docker compose exec postgres psql -U admin -d personal_ai -c "UPDATE users SET is_2fa_enabled = false, totp_secret = NULL WHERE username = 'admin';"
```

然后重新登录并设置新的 2FA。

## 📚 相关文档

- [密码设置和管理指南](./PASSWORD_SETUP_GUIDE.md) - 完整的密码管理文档
- [管理后台使用指南](./ADMIN_PANEL_GUIDE.md) - 管理后台功能说明
- [2FA 设置指南](./2FA_SETUP_GUIDE.md) - 双因素认证设置

## 🔗 相关文件

- `app/admin/router.py` - 设置页面路由
- `app/admin/first_run.py` - 首次运行中间件
- `app/admin/templates/setup.html` - 设置页面模板
- `app/admin/dependencies.py` - 会话管理

---

**最后更新**: 2026-01-11
**版本**: 1.0.0
