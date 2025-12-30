# RSS 解析优化需求文档 / RSS Parser Optimization Requirements

**需求编号**: REQ-2025-001
**创建日期**: 2025-12-30
**完成日期**: 2025-12-30
**状态**: 已完成 (Completed)
**优先级**: 中 (Medium)

---

## 📝 需求概述 / Overview

优化后端 RSS 解析功能，通过重构 feedparser 使用方式，提升代码质量、健壮性和可维护性。

Optimize backend RSS parsing functionality by refactoring feedparser usage to improve code quality, robustness, and maintainability.

---

## 🎯 用户故事 / User Story

**作为一名开发者 / As a developer**,
我想要拥有一个健壮、可维护的 RSS 解析组件 / I want a robust, maintainable RSS parsing component,
以便能够可靠地处理各种 RSS/Atom 格式 / So that I can reliably handle various RSS/Atom formats.

---

## ✅ 验收标准 / Acceptance Criteria

### 功能需求 / Functional Requirements

- [x] **独立的 RSS 解析器组件**
  - 创建 `backend/app/core/feed_parser.py` 模块
  - 封装所有 feedparser 操作
  - 提供清晰的 API 接口

- [x] **增强的内容提取**
  - 统一处理 `content` 和 `description` 字段
  - 支持 HTML 内容清理和纯文本提取
  - 处理多种内容编码格式

- [x] **健壮的错误处理**
  - 区分网络错误、解析错误、格式错误
  - 提供详细的错误日志
  - 优雅降级处理部分损坏的 feeds

- [x] **数据规范化**
  - 统一日期格式处理
  - 规范化作者信息
  - 标准化标签/分类提取

- [x] **性能优化**
  - 限制解析的条目数量（可配置）
  - 支持按需解析（仅解析需要的字段）

### 技术要求 / Technical Requirements

- 使用现有的 `feedparser>=6.0.10` 依赖
- 不引入新的外部库
- 保持与现有数据库模型的兼容性
- 添加类型注解（mypy 兼容）
- 编写单元测试

### API 设计 / API Design

```python
# 新的 FeedParser 组件接口
class FeedParser:
    async def parse_feed(self, url: str) -> FeedParseResult
    async def parse_feed_content(self, content: bytes) -> FeedParseResult

class FeedParseResult:
    feed_info: FeedInfo
    entries: List[FeedEntry]
    errors: List[ParseError]
    warnings: List[str]

class FeedInfo:
    title: str
    description: str
    link: str
    author: Optional[str]
    icon_url: Optional[str]
    updated_at: Optional[datetime]

class FeedEntry:
    id: str
    title: str
    content: str
    summary: Optional[str]
    author: Optional[str]
    link: Optional[str]
    image_url: Optional[str]
    tags: List[str]
    published_at: Optional[datetime]
    raw_metadata: Dict[str, Any]
```

---

## 🏗️ 实现计划 / Implementation Plan

### 阶段 1: 创建 FeedParser 组件
- [x] 创建 `backend/app/core/feed_parser.py`
- [x] 定义数据模型（Pydantic schemas）
- [x] 实现核心解析逻辑

### 阶段 2: 重构 SubscriptionService
- [x] 替换现有的 feedparser 调用
- [x] 使用新的 FeedParser 组件
- [x] 保持 API 兼容性

### 阶段 3: 测试和验证
- [x] 编写单元测试（26 个测试全部通过）
- [x] 测试各种 RSS/Atom 格式
- [x] 验证错误处理

### 阶段 4: 文档和集成
- [x] 更新代码文档
- [x] 验证与 Celery 任务的集成
- [x] 产品验收

---

## 📊 技术方案概述 / Technical Approach

### 架构设计

```
app/core/
├── feed_parser.py          # 核心解析器（新建）
└── feed_schemas.py         # 数据模型（新建）

app/domains/subscription/
└── services.py             # 重构使用 FeedParser
```

### 关键改进点

1. **内容提取优化**
   ```python
   # 当前: 简单的字段访问
   content = entry.get('content', [{}])[0].get('value')

   # 优化后: 统一的提取逻辑
   content = self._extract_content(entry)
   ```

2. **错误处理增强**
   ```python
   # 当前: 简单的异常捕获
   try:
       feed = feedparser.parse(response.content)
   except Exception as e:
       logger.error(f"Error: {e}")

   # 优化后: 分类错误处理
   try:
       result = await self.parser.parse_feed(url)
       if result.errors:
           await self._handle_parse_errors(result.errors)
   except NetworkError as e:
       # 网络错误处理
   except ParseError as e:
       # 解析错误处理
   ```

3. **数据规范化**
   ```python
   # 统一日期处理
   published_at = self._parse_date(entry)

   # 统一标签提取
   tags = self._extract_tags(entry)
   ```

---

## 📚 参考资料 / References

- [feedparser 官方文档](https://feedparser.readthedocs.io/)
- [RSS 2.0 规范](https://www.rssboard.org/rss-specification)
- [Atom 1.0 规范](https://www.rfc-editor.org/rfc/rfc4287)

---

## 📝 变更历史 / Changelog

| 日期 | 版本 | 变更内容 | 作者 |
|------|------|----------|------|
| 2025-12-30 | 1.0 | 初始需求文档 | Product Manager |
| 2025-12-30 | 1.1 | 完成所有实现和测试 | Backend Developer |

---

## 📊 完成总结 / Completion Summary

### 交付成果 / Deliverables

1. **核心组件** (`app/core/feed_parser.py` - 479 行)
   - FeedParser 类：支持 URL 和字节内容解析
   - 便捷函数：parse_feed_url() 和 parse_feed_bytes()
   - 完整的错误处理和日志记录

2. **数据模型** (`app/core/feed_schemas.py` - 221 行)
   - FeedParseResult: 完整解析结果
   - FeedInfo: Feed 基本信息
   - FeedEntry: 单个条目数据
   - ParseError: 错误详情模型
   - FeedParserConfig: 可配置解析选项

3. **服务重构** (`app/domains/subscription/services.py`)
   - 使用新 FeedParser 组件
   - 保持 API 兼容性
   - 增强错误处理

4. **测试覆盖** (`app/core/tests/test_feed_parser.py` - 269 行)
   - 26 个单元测试全部通过
   - 覆盖 RSS 和 Atom 格式
   - 网络错误处理测试

### 测试结果 / Test Results

```
======================= 26 passed, 15 warnings in 0.27s =======================
```

**文档状态**: 🟢 已完成
**所有验收标准均已通过 / All acceptance criteria met**
