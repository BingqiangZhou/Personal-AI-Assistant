# 播客音频转录功能文档

## 功能概述

播客音频转录功能允许用户将播客单集的音频自动转换为文本。该功能包括：

- 自动下载播客音频文件
- 音频格式转换（转换为MP3）
- 大文件智能分割（10MB chunks）
- 使用硅基流动API进行语音识别
- 转录结果自动合并和存储
- 实时进度跟踪
- 任务管理和错误处理

## 技术架构

### 核心组件

1. **AudioDownloader** - 音频文件下载器
   - 支持HTTP/HTTPS协议
   - 异步下载，支持进度回调
   - 自动处理网络错误

2. **AudioConverter** - 音频格式转换器
   - 使用FFmpeg进行格式转换
   - 转换为标准MP3格式（16kHz, 单声道）
   - 异步处理，支持进度跟踪

3. **AudioSplitter** - 音频文件分割器
   - 智能分割大文件为小片段
   - 可配置分割大小（默认10MB）
   - 保持音频时序完整性

4. **SiliconFlowTranscriber** - 硅基流动API集成
   - 支持并发转录请求
   - 自动限流和错误重试
   - 使用SenseVoiceSmall模型

5. **PodcastTranscriptionService** - 主服务类
   - 协调整个转录流程
   - 任务状态管理
   - 文件存储管理

### 数据模型

#### TranscriptionTask
转录任务模型，跟踪整个转录生命周期：

```python
class TranscriptionTask:
    id: int                    # 任务ID
    episode_id: int            # 播客单集ID
    status: TranscriptionStatus # 任务状态
    progress_percentage: float # 进度百分比
    original_audio_url: str   # 原始音频URL
    transcript_content: str   # 转录文本
    chunk_info: dict          # 分片信息
    error_message: str        # 错误信息
    # ... 其他字段
```

#### 任务状态（TranscriptionStatus）
- `pending` - 等待中
- `downloading` - 下载中
- `converting` - 格式转换中
- `splitting` - 文件分割中
- `transcribing` - 转录中
- `merging` - 合并结果中
- `completed` - 已完成
- `failed` - 失败
- `cancelled` - 已取消

## API接口

### 1. 启动转录任务

**POST** `/api/v1/podcast/episodes/{episode_id}/transcribe`

请求体：
```json
{
    "force_regenerate": false,  // 是否强制重新转录
    "chunk_size_mb": 10         // 分片大小（MB）
}
```

响应：
```json
{
    "id": 1,
    "episode_id": 123,
    "status": "pending",
    "progress_percentage": 0.0,
    "original_audio_url": "https://example.com/audio.mp3",
    "created_at": "2025-12-21T11:30:00Z",
    // ... 其他字段
}
```

### 2. 查询转录状态和结果

**GET** `/api/v1/podcast/episodes/{episode_id}/transcription`

查询参数：
- `include_content` - 是否包含完整转录文本（默认true）

响应：
```json
{
    "id": 1,
    "episode_id": 123,
    "status": "completed",
    "progress_percentage": 100.0,
    "transcript_content": "转录文本内容...",
    "transcript_word_count": 5000,
    "formatted_duration": "00:45:30",
    "formatted_processing_time": "125.50 seconds",
    // ... 其他字段
}
```

### 3. 获取实时状态

**GET** `/api/v1/podcast/transcriptions/{task_id}/status`

响应：
```json
{
    "task_id": 1,
    "episode_id": 123,
    "status": "transcribing",
    "progress": 65.0,
    "message": "正在进行语音识别",
    "current_chunk": 3,
    "total_chunks": 5,
    "eta_seconds": 180
}
```

### 4. 取消转录任务

**DELETE** `/api/v1/podcast/transcriptions/{task_id}`

响应：
```json
{
    "success": true,
    "message": "Transcription task cancelled successfully"
}
```

### 5. 获取转录任务列表

**GET** `/api/v1/podcast/transcriptions`

查询参数：
- `page` - 页码（默认1）
- `size` - 每页数量（默认20）
- `status_filter` - 状态筛选

响应：
```json
{
    "tasks": [...],
    "total": 100,
    "page": 1,
    "size": 20,
    "pages": 5
}
```

## 配置说明

在 `.env` 文件中添加以下配置：

```env
# 转录API配置
TRANSCRIPTION_API_URL=https://api.siliconflow.cn/v1/audio/transcriptions
TRANSCRIPTION_API_KEY=your_api_key_here

# 文件处理配置
TRANSCRIPTION_CHUNK_SIZE_MB=10          # 分片大小（MB）
TRANSCRIPTION_TARGET_FORMAT=mp3        # 目标格式
TRANSCRIPTION_TEMP_DIR=./temp/transcription
TRANSCRIPTION_STORAGE_DIR=./storage/podcasts

# 并发控制
TRANSCRIPTION_MAX_THREADS=4            # 最大并发数
TRANSCRIPTION_QUEUE_SIZE=100           # 队列大小
```

## 文件存储结构

转录完成的文件按照以下目录结构存储：

```
storage/podcasts/
├── 播客名称1/
│   ├── 分集名称1/
│   │   ├── original.mp3       # 原始音频文件
│   │   └── transcript.txt     # 转录文本
│   └── 分集名称2/
│       ├── original.mp3
│       └── transcript.txt
└── 播客名称2/
    └── ...
```

## 使用示例

### 通过API使用

1. **启动转录**
```bash
curl -X POST http://localhost:8000/api/v1/podcast/episodes/123/transcribe \
  -H "Authorization: Bearer your_token" \
  -H "Content-Type: application/json" \
  -d '{
    "force_regenerate": false,
    "chunk_size_mb": 10
  }'
```

2. **查询状态**
```bash
curl -X GET http://localhost:8000/api/v1/podcast/episodes/123/transcription \
  -H "Authorization: Bearer your_token"
```

3. **获取实时进度**
```bash
curl -X GET http://localhost:8000/api/v1/podcast/transcriptions/1/status \
  -H "Authorization: Bearer your_token"
```

### 通过Python代码使用

```python
from app.domains.podcast.transcription import PodcastTranscriptionService
from app.core.database import get_db_session

async def transcribe_episode(episode_id: int):
    async with get_db_session() as db:
        service = PodcastTranscriptionService(db)

        # 启动转录
        task = await service.start_transcription(episode_id)
        print(f"Started transcription task: {task.id}")

        # 查询状态
        while True:
            task = await service.get_transcription_status(task.id)
            print(f"Progress: {task.progress_percentage:.1f}%")

            if task.status.value in ["completed", "failed"]:
                break

            await asyncio.sleep(5)

        if task.status.value == "completed":
            print(f"Transcription completed: {task.transcript_content[:100]}...")
        else:
            print(f"Transcription failed: {task.error_message}")
```

## 性能优化建议

1. **并发控制**
   - 根据服务器性能调整 `TRANSCRIPTION_MAX_THREADS`
   - 避免过高的并发导致API限流

2. **分片大小**
   - 较小的分片（5MB）适合网络不稳定环境
   - 较大的分片（20MB）减少API调用次数，提高效率

3. **缓存策略**
   - 已转录的音频可缓存结果，避免重复转录
   - 实现转录结果的增量更新

4. **资源清理**
   - 定期清理临时转录目录
   - 设置转录任务的TTL（生存时间）

## 错误处理

常见错误及解决方案：

1. **下载失败**
   - 检查音频URL是否有效
   - 确认网络连接正常
   - 验证URL支持HTTP/HTTPS

2. **转换失败**
   - 确保FFmpeg已安装
   - 检查输入文件格式是否支持
   - 验证输出目录权限

3. **转录失败**
   - 检查硅基流动API密钥是否有效
   - 确认API配额充足
   - 验证音频文件格式和大小

4. **任务超时**
   - 调整下载和转录超时时间
   - 检查网络稳定性
   - 考虑减小分片大小

## 监控和日志

转录服务提供详细的日志记录：

- 任务创建和状态变更
- 下载、转换、转录各阶段的耗时
- 错误信息和堆栈跟踪
- 性能统计（文件大小、处理时间等）

日志级别：
- `INFO` - 正常流程记录
- `WARNING` - 非致命错误
- `ERROR` - 严重错误和失败

## 测试

运行单元测试：
```bash
cd backend
uv run pytest app/domains/podcast/tests/test_transcription.py -v
```

运行手动测试：
```bash
cd backend
uv run python test_transcription_manual.py
```

## 部署注意事项

1. **依赖安装**
   - 确保FFmpeg已安装在系统PATH中
   - 安装Python依赖：`uv add aiohttp aiofiles ffmpeg-python`

2. **目录权限**
   - 确保转录临时目录和存储目录有写权限
   - 建议使用SSD存储以提高I/O性能

3. **资源配置**
   - 转录任务CPU和内存密集，建议分配充足资源
   - 并发转录会消耗大量网络带宽

4. **安全考虑**
   - API密钥应通过环境变量配置
   - 限制用户并发转录任务数量
   - 实施文件大小限制和配额管理

## 未来改进

1. **功能增强**
   - 支持更多转录模型选择
   - 添加转录文本编辑功能
   - 支持多语言转录识别
   - 实现说话人识别（Diarization）

2. **性能优化**
   - 实现分布式转录处理
   - 添加转录结果缓存
   - 支断点续传功能
   - 优化内存使用

3. **用户体验**
   - WebSocket实时进度推送
   - 转录质量评分
   - 关键词提取和摘要
   - 转录结果导出功能