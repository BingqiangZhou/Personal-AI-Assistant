# 播客转录功能开发计划与任务分配

**文档ID**: DEV-PLAN-2025-001
**创建日期**: 2025-12-21
**负责人**: 产品经理
**预计总工期**: 10个工作日

## 1. 功能优先级矩阵

基于用户价值和实现复杂度评估：

| 功能 | 用户价值 | 实现复杂度 | 优先级 | 预计工期 |
|------|---------|-----------|-------|---------|
| 基础音频转录（后端） | 高 | 高 | P0 | 5天 |
| 转录文本显示（前端） | 高 | 中 | P0 | 4天 |
| Shownotes显示（前端） | 中 | 低 | P1 | 1天 |
| 音频同步功能 | 中 | 高 | P1 | 3天 |
| 转录文本搜索 | 中 | 中 | P2 | 2天 |

## 2. 开发阶段规划

### 阶段1：后端核心功能（第1-5天）
**目标**: 实现完整的音频转录后端服务

#### 第1天：架构搭建
- **任务**: 创建转录服务基础架构
- **负责人**: 后端工程师
- **交付物**:
  - 转录服务模块结构
  - Celery任务队列配置
  - 基础API路由

#### 第2天：音频处理
- **任务**: 实现音频文件处理功能
- **负责人**: 后端工程师
- **交付物**:
  - FFmpeg集成
  - 音频格式转换
  - 文件切割功能
  - 临时文件管理

#### 第3天：API集成
- **任务**: 集成硅基流动转录API
- **负责人**: 后端工程师
- **交付物**:
  - API客户端封装
  - 错误处理机制
  - 重试逻辑

#### 第4天：数据持久化
- **任务**: 完善数据库模型和存储
- **负责人**: 后端工程师
- **交付物**:
  - 数据库模型更新
  - 文件存储逻辑
  - 转录状态管理

#### 第5天：API接口和测试
- **任务**: 完善API接口和编写测试
- **负责人**: 后端工程师 + 测试工程师
- **交付物**:
  - 完整API文档
  - 单元测试
  - 集成测试

### 阶段2：前端基础功能（第6-9天）
**目标**: 实现转录文本和Shownotes显示

#### 第6天：数据层和API集成
- **任务**: 更新前端数据模型和API服务
- **负责人**: 前端工程师
- **交付物**:
  - PodcastEpisodeModel扩展
  - API服务更新
  - Provider配置

#### 第7天：UI组件开发
- **任务**: 开发转录文本显示组件
- **负责人**: 前端工程师
- **交付物**:
  - 转录文本查看器
  - Shownotes显示组件
  - TabBar集成

#### 第8天：交互功能
- **任务**: 实现搜索和文本操作功能
- **负责人**: 前端工程师
- **交付物**:
  - 文本搜索功能
  - 复制分享功能
  - 文本大小调节

#### 第9天：优化和测试
- **任务**: UI优化和测试
- **负责人**: 前端工程师 + 测试工程师
- **交付物**:
  - UI动画优化
  - Widget测试
  - 集成测试

### 阶段3：高级功能（第10天+）
**目标**: 实现音频同步等高级功能

#### 第10天：音频同步（可选）
- **任务**: 实现音频播放与文本同步
- **负责人**: 前端工程师
- **交付物**:
  - 音频时间戳映射
  - 自动滚动和高亮
  - 点击跳转功能

## 3. 详细任务分解

### 3.1 后端任务清单

#### T1.1 创建转录服务模块
```
文件路径:
- backend/app/domains/podcast/services/transcription_service.py
- backend/app/domains/podcast/tasks/transcription_tasks.py
- backend/app/domains/podcast/api/transcription_routes.py

任务内容:
1. 创建TranscriptionService类
2. 定义转录任务队列
3. 配置Celery worker
4. 创建基础API端点
```

#### T1.2 实现音频处理
```
文件路径:
- backend/app/shared/utils/audio_processor.py
- backend/app/core/config/transcription_config.py

任务内容:
1. 实现AudioProcessor类
2. 集成FFmpeg命令行工具
3. 实现格式转换方法
4. 实现文件切割方法
5. 添加临时文件清理逻辑
```

#### T1.3 集成转录API
```
文件路径:
- backend/app/integration/siliconflow/client.py
- backend/app/domains/podcast/services/transcription_service.py

任务内容:
1. 创建SiliconFlowClient
2. 实现文件上传和转录请求
3. 处理API响应和错误
4. 实现重试机制
```

#### T1.4 数据库更新
```
文件路径:
- backend/app/domains/podcast/models.py
- backend/alembic/versions/

任务内容:
1. 添加转录相关字段到PodcastEpisode
2. 创建TranscriptionTask模型
3. 生成数据库迁移文件
4. 更新schemas.py
```

### 3.2 前端任务清单

#### T2.1 数据模型更新
```
文件路径:
- frontend/lib/features/podcast/data/models/podcast_episode_model.dart
- frontend/lib/features/podcast/data/services/podcast_api_service.dart
- frontend/lib/features/podcast/presentation/providers/episode_detail_provider.dart

任务内容:
1. 添加转录状态字段
2. 添加TranscriptionStatus枚举
3. 创建TextSegment模型
4. 更新API调用方法
5. 实现状态管理逻辑
```

#### T2.2 UI组件开发
```
文件路径:
- frontend/lib/features/podcast/presentation/widgets/episode_transcript_widget.dart
- frontend/lib/features/podcast/presentation/widgets/episode_shownotes_widget.dart
- frontend/lib/features/podcast/presentation/widgets/transcript_search_bar.dart

任务内容:
1. 创建转录文本显示组件
2. 实现HTML渲染的Shownotes组件
3. 开发搜索栏组件
4. 集成到播客详情页
```

#### T2.3 页面集成
```
文件路径:
- frontend/lib/features/podcast/presentation/pages/podcast_episode_detail_page.dart

任务内容:
1. 添加TabBar到详情页
2. 集成转录和Shownotes组件
3. 实现下拉刷新
4. 处理加载和错误状态
```

## 4. 任务分配表

| 任务编号 | 任务名称 | 负责人 | 开始日期 | 截止日期 | 状态 | 依赖 |
|---------|---------|-------|---------|---------|------|------|
| T1.1 | 创建转录服务模块 | 后端工程师 | Day 1 | Day 1 | 待开始 | - |
| T1.2 | 实现音频处理 | 后端工程师 | Day 2 | Day 2 | 待开始 | T1.1 |
| T1.3 | 集成转录API | 后端工程师 | Day 3 | Day 3 | 待开始 | T1.2 |
| T1.4 | 数据库更新 | 后端工程师 | Day 4 | Day 4 | 待开始 | T1.3 |
| T1.5 | API测试 | 后端+测试 | Day 5 | Day 5 | 待开始 | T1.4 |
| T2.1 | 数据模型更新 | 前端工程师 | Day 6 | Day 6 | 待开始 | T1.5 |
| T2.2 | UI组件开发 | 前端工程师 | Day 7 | Day 8 | 待开始 | T2.1 |
| T2.3 | 页面集成 | 前端工程师 | Day 8 | Day 8 | 待开始 | T2.2 |
| T2.4 | 前端测试 | 前端+测试 | Day 9 | Day 9 | 待开始 | T2.3 |
| T3.1 | 音频同步 | 前端工程师 | Day 10 | Day 10+ | 可选 | T2.4 |

## 5. 风险管理

### 5.1 技术风险
| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|---------|
| FFmpeg安装问题 | 高 | 中 | 提前准备Docker镜像 |
| 硅基流动API限制 | 中 | 低 | 实现降级方案 |
| 大文件处理性能 | 中 | 中 | 分块处理和流式传输 |
| 前端渲染性能 | 中 | 低 | 虚拟滚动优化 |

### 5.2 进度风险
| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|---------|
| 开发延期 | 高 | 中 | 预留缓冲时间 |
| 需求变更 | 中 | 低 | 模块化设计 |
| 资源冲突 | 中 | 低 | 合理的任务分配 |

## 6. 每日站会检查点

### Day 1 检查点
- [ ] 转录服务模块创建完成
- [ ] Celery配置正确
- [ ] 基础API路由可访问

### Day 2 检查点
- [ ] FFmpeg集成成功
- [ ] 音频切割功能测试通过
- [ ] 临时文件管理正常

### Day 3 检查点
- [ ] 硅基流动API集成完成
- [ ] 错误处理机制就位
- [ ] 可以成功转录小文件

### Day 4 检查点
- [ ] 数据库模型更新完成
- [ ] 迁移脚本执行成功
- [ ] 转录状态可正确更新

### Day 5 检查点
- [ ] 所有后端API测试通过
- [ ] 文档更新完整
- [ ] 性能测试达标

### Day 6 检查点
- [ ] 前端模型更新完成
- [ ] API集成成功
- [ ] 可以获取转录状态

### Day 7 检查点
- [ ] 转录文本组件完成
- [ ] Shownotes显示正常
- [ ] 基础交互功能正常

### Day 8 检查点
- [ ] 搜索功能实现
- [ ] 页面集成完成
- [ ] UI符合Material 3规范

### Day 9 检查点
- [ ] 所有前端测试通过
- [ ] 性能优化完成
- [ ] 准备演示

## 7. 交付物清单

### 后端交付物
- [ ] 转录服务完整代码
- [ ] API文档
- [ ] 数据库迁移脚本
- [ ] 单元测试和集成测试
- [ ] 部署配置

### 前端交付物
- [ ] UI组件代码
- [ ] 页面集成代码
- [ ] Widget测试
- [ ] UI/UX设计文件
- [ ] 用户使用指南

### 文档交付物
- [ ] 技术设计文档
- [ ] API接口文档
- [ ] 用户手册
- [ ] 部署指南
- [ ] 测试报告

## 8. 验收标准

详细验收标准请参考：
- [podcast-audio-transcription-feature.md](./podcast-audio-transcription-feature.md#验收标准)
- [podcast-frontend-transcription-display.md](./podcast-frontend-transcription-display.md#验收标准)

## 9. 发布计划

### 内部测试（Day 9-10）
- 开发团队功能验证
- 基本功能测试
- 性能基准测试

### 用户测试（Day 11-12）
- 邀请种子用户测试
- 收集反馈
- Bug修复

### 正式发布（Day 13）
- 部署到生产环境
- 发布说明
- 用户培训材料

## 10. 后续优化计划

- 性能监控和优化
- 用户反馈收集
- 功能迭代规划
- 新功能评估（如AI摘要增强）