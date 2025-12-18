# Docker网络问题解决方案

## 问题描述
在中国大陆，Docker Hub访问可能很慢或失败，出现类似错误：
```
failed to fetch anonymous token: Get "https://auth.docker.io/token?scope=repository%3Alibrary%2Fpython%3Apull&service=registry.docker.io": dial tcp 128.242.245.212:443
```

## 解决方案

### 方案1：配置Docker国内镜像源（推荐）

1. **Windows - Docker Desktop**
   - 打开Docker Desktop
   - 点击设置 (Settings)
   - 选择 Docker Engine
   - 添加以下配置：
   ```json
   {
     "registry-mirrors": [
       "https://docker.mirrors.ustc.edu.cn",
       "https://hub-mirror.c.163.com",
       "https://mirror.baidubce.com"
     ]
   }
   ```
   - 点击 Apply & Restart

2. **Linux - 修改daemon.json**
   ```bash
   sudo mkdir -p /etc/docker
   sudo tee /etc/docker/daemon.json <<EOF
   {
     "registry-mirrors": [
       "https://docker.mirrors.ustc.edu.cn",
       "https://hub-mirror.c.163.com",
       "https://mirror.baidubce.com"
     ]
   }
   EOF
   sudo systemctl restart docker
   ```

### 方案2：使用代理

如果你有代理，可以配置Docker使用代理：

**Windows - Docker Desktop**
- 设置 → Proxies
- 配置HTTP/HTTPS代理

**Linux**
```bash
sudo systemctl edit docker.service
# 添加以下内容：
[Service]
Environment="HTTP_PROXY=http://proxy.example.com:8080"
Environment="HTTPS_PROXY=http://proxy.example.com:8080"
Environment="NO_PROXY=localhost,127.0.0.1"
```

### 方案3：手动拉取镜像

如果上述方法仍然有问题，可以尝试：

1. **使用国内镜像仓库**
```bash
docker pull registry.cn-hangzhou.aliyuncs.com/library/python:3.11-slim
docker tag registry.cn-hangzhou.aliyuncs.com/library/python:3.11-slim python:3.11-slim
```

2. **修改Dockerfile使用国内基础镜像**
```dockerfile
FROM registry.cn-hangzhou.aliyuncs.com/library/python:3.11-slim
```

或者使用我已经创建的 `Dockerfile.cn`：
```cmd
# 备份原文件
copy Dockerfile Dockerfile.backup

# 使用国内优化版本
copy Dockerfile.cn Dockerfile
```

### 方案4：使用VPN

- 启动VPN后重新构建
- 确保VPN允许Docker流量通过

## 验证配置

检查Docker镜像源是否配置成功：
```bash
docker info | grep -i registry
```

应该能看到你配置的镜像源。

## 重新构建

配置完成后，清理旧镜像并重新构建：
```bash
# 进入docker目录
cd docker

# 清理旧的构建缓存
docker builder prune -f

# 重新构建
docker compose -f docker-compose.podcast.yml up -d --build
```

## 其他建议

1. **使用阿里云容器镜像服务**
   - 访问：https://cr.console.aliyun.com/cn-hangzhou/instances
   - 免费个人版

2. **修改Docker Compose的PostgreSQL镜像**
   ```yaml
   image: registry.cn-hangzhou.aliyuncs.com/library/postgres:15-alpine
   ```

## 常见国内镜像源

```json
{
  "registry-mirrors": [
    "https://docker.mirrors.ustc.edu.cn",
    "https://hub-mirror.c.163.com",
    "https://mirror.baidubce.com",
    "https://dockerhub.azk8s.cn",
    "https://docker.m.daocloud.io"
  ]
}
```

选择其中一个即可，建议使用离你最近的镜像源。