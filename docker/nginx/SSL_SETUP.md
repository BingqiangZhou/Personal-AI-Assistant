# SSL证书配置指南 / SSL Certificate Setup Guide

## 概述 / Overview

本指南介绍如何为Nginx配置SSL证书以启用HTTPS。

This guide explains how to configure SSL certificates for Nginx to enable HTTPS.

---

## 方法一：使用 Let's Encrypt (推荐生产环境)

### 方法1A: 使用 Certbot 获取免费证书

#### 1. 安装 Certbot

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install certbot

# CentOS/RHEL
sudo yum install certbot

# macOS
brew install certbot
```

#### 2. 获取证书

##### 选项A: 独立模式（需要停止占用80端口的进程）

```bash
# 停止Docker中的Nginx
cd docker
docker-compose stop nginx

# 获取证书
sudo certbot certonly --standalone -d your-domain.com -d www.your-domain.com

# 重启Nginx
docker-compose start nginx
```

##### 选项B: DNS 验证（推荐，不需要停止服务）

```bash
# 使用CloudFlare DNS验证
sudo certbot certonly --dns-cloudflare --dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini -d your-domain.com

# 使用其他DNS提供商
sudo certbot certonly --manual --preferred-challenges dns -d your-domain.com
```

#### 3. 复制证书到项目目录

```bash
# 证书位置 (Ubuntu/Debian)
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem docker/nginx/cert/
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem docker/nginx/cert/

# 设置权限
sudo chmod 644 docker/nginx/cert/fullchain.pem
sudo chmod 600 docker/nginx/cert/privkey.pem
```

#### 4. 更新 Nginx 配置

编辑 `docker/nginx/conf.d/default-ssl.conf`:
```nginx
server_name your-domain.com;  # 修改为你的域名
```

#### 5. 启用 HTTPS 配置

```bash
# 重命名配置文件
cd docker/nginx/conf.d
mv default.conf default.conf.bak
mv default-ssl.conf default.conf

# 重启 Nginx
cd ..
docker-compose restart nginx
```

---

## 方法二：使用自签名证书（开发环境）

### 生成自签名证书

```bash
# 创建证书
cd docker/nginx/cert
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout privkey.pem \
  -out fullchain.pem \
  -subj "/C=CN/ST=State/L=City/O=Organization/CN=localhost"

# 设置权限
chmod 600 privkey.pem
chmod 644 fullchain.pem
```

### 更新配置

编辑 `docker/nginx/conf.d/default-ssl.conf`:
```nginx
server_name localhost;  # 使用localhost
```

---

## 方法三：使用商业证书

### 购买并下载证书

从证书颁发机构（CA）购买SSL证书后，通常会获得以下文件：
- `your-domain.crt` - 证书文件
- `your-domain.key` - 私钥文件
- `ca-bundle.crt` - CA证书链（可选）

### 转换证书格式

```bash
# 合并证书和CA链
cat your-domain.crt ca-bundle.crt > fullchain.pem

# 复制私钥
cp your-domain.key privkey.pem

# 移动到项目目录
mv fullchain.pem docker/nginx/cert/
mv privkey.pem docker/nginx/cert/
```

---

## 证书自动续期 / Certificate Auto-Renewal

### 设置 Let's Encrypt 证书自动续期

```bash
# 编辑 crontab
sudo crontab -e

# 添加每天凌晨2点检查续期
0 2 * * * certbot renew --quiet --post-hook "cd /path/to/project/docker && docker-compose exec nginx nginx -s reload"
```

### 测试续期

```bash
sudo certbot renew --dry-run
```

---

## 配置验证 / Configuration Verification

### 检查证书有效期

```bash
openssl x509 -in docker/nginx/cert/fullchain.pem -text -noout | grep "Not After"
```

### 测试 Nginx 配置

```bash
cd docker
docker-compose exec nginx nginx -t
```

### 检查 SSL 配置

访问以下URL测试你的SSL配置：
- https://www.ssllabs.com/ssltest/
- https://www.sslshopper.com/ssl-checker.html

---

## 常见问题 / Troubleshooting

### 1. 证书权限错误

```bash
chmod 600 docker/nginx/cert/privkey.pem
chmod 644 docker/nginx/cert/fullchain.pem
```

### 2. Nginx 启动失败

```bash
# 查看日志
docker-compose logs nginx

# 测试配置
docker-compose exec nginx nginx -t
```

### 3. 浏览器显示不安全

- 确保使用正确的域名
- 检查证书链是否完整
- 清除浏览器缓存

### 4. 端口冲突

```bash
# 检查端口占用
netstat -tuln | grep -E ':(80|443) '

# 停止占用端口的服务
sudo systemctl stop apache2  # 如果运行Apache
```

---

## 安全建议 / Security Recommendations

1. **使用强加密**: 确保nginx配置中使用TLSv1.2和TLSv1.3
2. **启用HSTS**: 添加Strict-Transport-Security头
3. **定期更新**: 保持Nginx和OpenSSL版本最新
4. **保护私钥**: 确保私钥文件权限为600
5. **监控过期**: 设置证书过期提醒

---

## 参考 / References

- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [Nginx SSL Module Documentation](https://nginx.org/en/docs/http/ngx_http_ssl_module.html)
