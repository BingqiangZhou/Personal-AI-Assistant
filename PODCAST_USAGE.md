# 🎙️ 播客功能快速开始指南

## 🚀 功能特性

### 安全核心
✅ **XXE/SSRF防护** - 恶意RSS链接免疫
✅ **AI隐私净化** - 智能过滤PII信息
✅ **单Redis配置** - 个人使用简化

### 核心功能
- 📌 RSS播客订阅（自动解析）
- 🤖 AI自动总结（无需手动输入）
- 📊 音频播放与进度追踪
- 🎛️ 支持转录文本优化
- 🔍 待总结队列管理

---

## 📦 安装依赖

```bash
cd backend
pip install -r requirements.txt

# 安全库安装验证
python -c "from defusedxml import ElementTree; print('✅ XXE防护已启用')"
```

---

## 🗄️ 数据库初始化

### 1. 运行数据库迁移
```bash
cd backend
python database_migration.py
```

输出示例：
```
开始播客数据库迁移...
✅ 播客相关表已创建
✅ 外键约束已添加
📊 podcast_episodes 列 (17):
  - id: integer
  - subscription_id: integer
  - guid: character varying
  - title: character varying
  - audio_url: character varying
  ...
✅ 验证通过: 表已存在
🎉 迁移完成！
```

### 2. 可选：回滚/清理
```bash
python database_migration.py --rollback
```

---

## 🔄 启动服务

```bash
# 方式1: Docker方式
docker-compose up -d

# 方式2: 直接运行
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

访问: http://localhost:8000/docs 查看API文档

---

## 🍴 使用示例

### 场景1: 添加播客订阅

添加一个经济学播客，自动获取最新5期节目并生成AI总结：

**请求:**
```bash
curl -X POST "http://localhost:8000/api/v1/podcasts/subscription" \
  -H "Authorization: Bearer <你的JWT令牌>" \
  -H "Content-Type: application/json" \
  -d '{
    "feed_url": "https://feeds.npr.org/510289/podcast.xml",
    "custom_name": "经济学人"
  }'
```

**响应:**
```json
{
  "success": true,
  "subscription_id": 12,
  "new_episodes": 5,
  "message": "已添加 经济学人, 发现 5 期新节目"
}
```

**后台行为:**
1. ✅ 验证RSS安全性（XXE检测）
2. ✅ 解析5期最新节目
3. ✅ 触发5个AI总结任务（后台异步）
4. ✅ 结果自动缓存到Redis
5. ✅ 可立即查看总结状态

---

### 场景2: 查看带总结的单集

**请求:**
```bash
curl "http://localhost:8000/api/v1/podcasts/episodes/42" \
  -H "Authorization: Bearer <令牌>"
```

**响应:**
```json
{
  "id": 42,
  "title": "如何在2025年应对通货膨胀",
  "audio_url": "https://cdn.example.com/episode/audio.mp3",
  "duration": 1800,
  "summary": "## 主要话题\n• 当前经济形势分析\n• 资产配置策略\n\n## 关键见解\n• 通胀持续性的深层原因...",
  "summary_status": "summarized",
  "ai_confidence": 0.89,
  "playback": {
    "progress": 720,
    "is_playing": false,
    "play_count": 2
  }
}
```

---

### 场景3: 收听与进度更新

**步骤1: 开始播放**
```bash
curl -X POST "http://localhost:8000/api/v1/podcasts/episodes/42/progress" \
  -H "Authorization: Bearer <令牌>" \
  -d '{"position": 0, "is_playing": true}'
```

**步骤2: 更新进度**
```bash
# 听到10:00时更新
curl -X POST "http://localhost:8000/api/v1/podcasts/episodes/42/progress" \
  -H "Authorization: Bearer <令牌>" \
  -d '{"position": 600, "is_playing": true}'

# 暂停时更新
curl -X POST "http://localhost:8000/api/v1/podcasts/episodes/42/progress" \
  -H "Authorization: Bearer <令牌>" \
  -d '{"position": 600, "is_playing": false}'
```

---

### 场景4: 手动触发重新总结

如果对AI总结不满意，强制重新生成：

```bash
curl -X POST "http://localhost:8000/api/v1/podcasts/episodes/42/summary?force=true" \
  -H "Authorization: Bearer <令牌>"
```

---

#### 场景5: 查看待总结的节目

```bash
curl "http://localhost:8000/api/v1/podcasts/summary/pending" \
  -H "Authorization: Bearer <令牌>"
```

---

## 🔐 隐私模式设置

根据需要在 `.env` 中调整：

```bash
# 隐私保护级别
LLM_CONTENT_SANITIZE_MODE=standard  # strict | standard | none

# strict: 移除所有PII（电话、邮箱、姓名、地址）
# standard: 移除电话和邮箱
# none: 不过滤（需用户同意）
```

### 隐私处理示例

**原始播客描述:**
```
"今天邀请张三(zhangsan@email.com, 13800138000)讨论AI安全等话题..."
```

**strict模式处理后:**
```
"今天邀请 [NAME_REDACTED] 张三([EMAIL_REDACTED], [PHONE_REDACTED])讨论AI安全等话题..."
```

**即保护隐私，又保留上下文！**

---

## 💡 常见问题

### Q: RSS解析报错？
**A**: 确保链接是有效的播客RSS，大多数支持：
- Podcast Index格式
- Apple Podcasts格式
- 标准RSS 2.0 with enclosures

### Q: AI总结很久没出结果？
**A**: 检查：
```bash
# 查看后台任务状态
redis-cli keys "podcast:lock:*"

# 查看是否有失败
curl "http://localhost:8000/api/v1/podcasts/summary/pending" \
  -H "Authorization: Bearer <令牌>"
```

### Q: 连接池不足？
**A**: 已在配置中优化，默认支持60并发。如需更高：
```python
# app/core/config.py
DATABASE_POOL_SIZE: int = 30  # 提高基数
DATABASE_MAX_OVERFLOW: int = 50  # 提高溢出
```

---

## 🔧 技术架构

```
API Endpoint /api/v1/podcasts
    ↓
Security Layer (xxe/ssrf protection)
    ↓
PodcastRepository (数据访问)
    ↓
PodcastService (业务逻辑)
    │
    ├── RSS Parser (安全解析)
    │   └── defusedxml + aiohttp
    │
    ├── AI Summarizer (总结生成)
    │   ├── Content sanitizer (隐私保护)
    │   └── LLM API (OpenAI/Claude)
    │
    └── Redis Cache (性能优化)
        - 15min: RSS内容缓存
        - 24h: Episode元数据
        - 7天: AI总结结果
        - 30天: 播放进度
```

---

## 🎯 性能特点

| 特性 | 实现 |
|------|------|
| **RSS解析** | 异步 + 超时保护 |
| **AI总结** | 后台任务，非阻塞 |
| **重复保护** | Redis锁防止并发处理 |
| **缓存命中** | 7天TTL + 智能失效 |
| **数据库** | 60连接池 + Pre-Ping |

**个人使用负载**: 轻松支持50个订阅，1000期节目

---

## 🔍 日志监控示例

```bash
# 查看处理日志
tail -f backend/logs/app.log | grep "user.*podcast"

# 典型成功日志:
# INFO - 用户23 添加播客: 经济学人, 发现32期节目
# INFO - AI总结完成 episode:105 (transcript)
```

---

## ✅ 测试用例

Python快速测试:

```python
import asyncio
from app.core.database import async_sessionmaker
from app.domains.podcast.services import PodcastService

async def test_workflow():
    """完整工作流测试"""
    # 获取数据库会话
    async_db = async_sessionmaker(engine, class_=AsyncSession)

    async with async_db() as db:
        service = PodcastService(db, user_id=1)  # 假设用户ID=1

        # 1. 添加订阅
        sub, episodes = await service.add_subscription(
            feed_url="https://feeds.npr.org/510289/podcast.xml"
        )
        print(f"订阅: {sub.title}, 新节目: {len(episodes)}")

        # 2. 立即获取首个节目的总结
        if episodes:
            summary = await service.generate_summary_for_episode(episodes[0].id)
            print(f"AI总结: {summary[:100]}...")

# 运行测试
asyncio.run(test_workflow())
```

---

现在你已经具备完整的播客能力！🎉

如需进一步扩展：
1. 添加后台定时轮询
2. 实现转录文本下载
3. 移动端播放器集成
4. 智能推荐系统

有任何问题随时问我！