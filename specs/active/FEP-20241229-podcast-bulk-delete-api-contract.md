# API Contract: 批量删除播客订阅 / Bulk Delete Podcast Subscriptions

## Overview / 概述

本文档定义了批量删除播客订阅功能的 API 契约，包括请求格式、响应格式、错误处理和业务逻辑。

This document defines the API contract for the bulk delete podcast subscriptions feature, including request format, response format, error handling, and business logic.

---

## Endpoint / 端点

### DELETE /api/v1/podcasts/subscriptions/bulk

**Description / 描述**: 批量删除用户的播客订阅及其所有关联数据 / Bulk delete user's podcast subscriptions and all related data

**Authentication / 认证**: Required (JWT Bearer Token) / 必需（JWT Bearer Token）

---

## Request Format / 请求格式

### Headers / 请求头

```http
DELETE /api/v1/podcasts/subscriptions/bulk HTTP/1.1
Host: api.example.com
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json
```

### Request Body / 请求体

```json
{
  "subscription_ids": [1, 2, 3, 4, 5]
}
```

### Request Schema / 请求 Schema (Pydantic)

```python
from typing import List
from pydantic import BaseModel, Field, field_validator


class PodcastSubscriptionBulkDelete(BaseModel):
    """批量删除播客订阅请求 / Bulk delete podcast subscriptions request"""

    subscription_ids: List[int] = Field(
        ...,
        description="List of subscription IDs to delete / 要删除的订阅ID列表",
        min_length=1,
        max_length=100
    )

    @field_validator('subscription_ids')
    @classmethod
    def validate_subscription_ids(cls, v):
        """验证订阅ID列表 / Validate subscription IDs list"""
        if not v:
            raise ValueError('subscription_ids cannot be empty / subscription_ids不能为空')
        if len(v) > 100:
            raise ValueError('Cannot delete more than 100 subscriptions at once / 不能一次删除超过100个订阅')
        if any(id <= 0 for id in v):
            raise ValueError('All subscription IDs must be positive integers / 所有订阅ID必须是正整数')
        # 去重 / Remove duplicates
        return list(set(v))


# Example usage / 使用示例
request = PodcastSubscriptionBulkDelete(subscription_ids=[1, 2, 3, 4, 5])
```

### Request Validation Rules / 请求验证规则

| Field / 字段 | Type / 类型 | Required / 必需 | Validation / 验证 |
|--------------|-------------|-----------------|------------------|
| subscription_ids | List[int] | Yes / 是 | - Length: 1-100 / 长度: 1-100<br>- All IDs > 0 / 所有ID > 0<br>- Auto deduplicate / 自动去重 |

---

## Response Format / 响应格式

### Success Response (200 OK) / 成功响应

```json
{
  "success_count": 4,
  "failed_count": 1,
  "errors": [
    {
      "subscription_id": 3,
      "message": "Subscription not found or no permission / 订阅不存在或无权限"
    }
  ]
}
```

### Response Schema / 响应 Schema (Pydantic)

```python
from typing import List, Optional
from pydantic import BaseModel, Field


class BulkDeleteError(BaseModel):
    """批量删除错误详情 / Bulk delete error detail"""

    subscription_id: int = Field(..., description="Subscription ID that failed to delete / 删除失败的订阅ID")
    message: str = Field(..., description="Error message / 错误消息")


class PodcastSubscriptionBulkDeleteResponse(BaseModel):
    """批量删除播客订阅响应 / Bulk delete podcast subscriptions response"""

    success_count: int = Field(
        ...,
        description="Number of subscriptions successfully deleted / 成功删除的订阅数量",
        ge=0
    )
    failed_count: int = Field(
        ...,
        description="Number of subscriptions that failed to delete / 删除失败的订阅数量",
        ge=0
    )
    errors: List[BulkDeleteError] = Field(
        default_factory=list,
        description="List of errors for failed deletions / 删除失败的错误列表"
    )

    @property
    def total_requested(self) -> int:
        """Total number of subscriptions requested to delete / 请求删除的订阅总数"""
        return self.success_count + self.failed_count


# Example usage / 使用示例
response = PodcastSubscriptionBulkDeleteResponse(
    success_count=4,
    failed_count=1,
    errors=[
        BulkDeleteError(subscription_id=3, message="Subscription not found or no permission")
    ]
)
```

### Response Fields / 响应字段

| Field / 字段 | Type / 类型 | Description / 描述 |
|--------------|-------------|-------------------|
| success_count | int | 成功删除的订阅数量 / Number of subscriptions successfully deleted |
| failed_count | int | 删除失败的订阅数量 / Number of subscriptions that failed to delete |
| errors | List[BulkDeleteError] | 删除失败的错误详情列表 / List of error details for failed deletions |
| errors[].subscription_id | int | 删除失败的订阅ID / Subscription ID that failed |
| errors[].message | str | 错误消息 / Error message |

---

## Error Responses / 错误响应

### 400 Bad Request / 请求错误

```json
{
  "detail": "Invalid request body / 无效的请求体"
}
```

**Causes / 原因**:
- Request body is missing / 请求体缺失
- Invalid JSON format / JSON 格式无效
- Validation failed (empty list, too many IDs, invalid IDs) / 验证失败（空列表、ID过多、ID无效）

### 401 Unauthorized / 未授权

```json
{
  "detail": "Authentication required / 需要身份验证"
}
```

**Causes / 原因**:
- Missing or invalid JWT token / JWT token 缺失或无效
- Token expired / Token 过期

### 403 Forbidden / 禁止访问

```json
{
  "detail": "No permission to delete one or more subscriptions / 无权限删除一个或多个订阅"
}
```

**Causes / 原因**:
- One or more subscriptions do not belong to the current user / 一个或多个订阅不属于当前用户

### 404 Not Found / 未找到

```json
{
  "detail": "One or more subscriptions not found / 一个或多个订阅不存在"
}
```

**Causes / 原因**:
- One or more subscription IDs do not exist / 一个或多个订阅ID不存在

### 500 Internal Server Error / 服务器内部错误

```json
{
  "detail": "Internal server error / 服务器内部错误"
}
```

**Causes / 原因**:
- Database connection error / 数据库连接错误
- Database transaction error / 数据库事务错误
- Unexpected server error / 意外的服务器错误

---

## Business Logic / 业务逻辑

### Processing Flow / 处理流程

```
1. Validate JWT token
   ↓
2. Validate request body (subscription_ids)
   ↓
3. Verify all subscriptions belong to current user
   ↓
4. Begin database transaction
   ↓
5. For each subscription_id:
   a. Delete related conversations (podcast_conversations table)
   b. Delete related transcription tasks (podcast_transcription_tasks table)
   c. Delete related playback progress (podcast_playback_states table)
   d. Delete related episodes (podcast_episodes table)
   e. Delete subscription (subscriptions table)
   ↓
6. Commit transaction
   ↓
7. Return response with success/failure counts
```

### Deletion Order / 删除顺序

**Important / 重要**: Must delete related data in the following order to avoid foreign key constraint violations / 必须按以下顺序删除相关数据以避免外键约束冲突:

1. `podcast_conversations` (对话历史 / Conversation history)
2. `podcast_transcription_tasks` (转录任务 / Transcription tasks)
3. `podcast_playback_states` (播放进度 / Playback progress)
4. `podcast_episodes` (单集 / Episodes)
5. `subscriptions` (订阅 / Subscriptions)

### Transaction Handling / 事务处理

- **Atomicity / 原子性**: All deletions for a single subscription must succeed or fail together / 单个订阅的所有删除必须一起成功或失败
- **Consistency / 一致性**: Database constraints must be satisfied / 必须满足数据库约束
- **Isolation / 隔离性**: Concurrent deletions should not interfere / 并发删除不应相互干扰
- **Durability / 持久性**: Once committed, data must persist / 一旦提交，数据必须持久化

**Implementation / 实现**:

```python
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from app.domains.subscription.models import Subscription
from app.domains.podcast.models import PodcastEpisode, PodcastConversation, PodcastTranscriptionTask, PodcastPlaybackState


async def remove_subscriptions_bulk(
    db: AsyncSession,
    user_id: int,
    subscription_ids: List[int]
) -> dict:
    """
    Batch delete subscriptions with all related data
    批量删除订阅及其所有关联数据
    """
    success_count = 0
    failed_count = 0
    errors = []

    for sub_id in subscription_ids:
        try:
            # Use a nested transaction for each subscription
            # 为每个订阅使用嵌套事务
            async with db.begin_nested():
                # 1. Verify ownership
                # 1. 验证所有权
                stmt = select(Subscription).where(
                    Subscription.id == sub_id,
                    Subscription.user_id == user_id
                )
                result = await db.execute(stmt)
                subscription = result.scalar_one_or_none()

                if not subscription:
                    raise ValueError("Subscription not found or no permission")

                # 2. Delete related conversations
                # 2. 删除相关对话
                await db.execute(
                    delete(PodcastConversation).where(
                        PodcastConversation.episode_id.in_(
                            select(PodcastEpisode.id).where(
                                PodcastEpisode.subscription_id == sub_id
                            )
                        )
                    )
                )

                # 3. Delete related transcription tasks
                # 3. 删除相关转录任务
                await db.execute(
                    delete(PodcastTranscriptionTask).where(
                        PodcastTranscriptionTask.episode_id.in_(
                            select(PodcastEpisode.id).where(
                                PodcastEpisode.subscription_id == sub_id
                            )
                        )
                    )
                )

                # 4. Delete related playback states
                # 4. 删除相关播放进度
                await db.execute(
                    delete(PodcastPlaybackState).where(
                        PodcastPlaybackState.episode_id.in_(
                            select(PodcastEpisode.id).where(
                                PodcastEpisode.subscription_id == sub_id
                            )
                        )
                    )
                )

                # 5. Delete episodes
                # 5. 删除单集
                await db.execute(
                    delete(PodcastEpisode).where(
                        PodcastEpisode.subscription_id == sub_id
                    )
                )

                # 6. Delete subscription
                # 6. 删除订阅
                await db.execute(
                    delete(Subscription).where(
                        Subscription.id == sub_id
                    )
                )

            success_count += 1

        except Exception as e:
            failed_count += 1
            errors.append({
                "subscription_id": sub_id,
                "message": str(e)
            })
            # Continue with next subscription
            # 继续处理下一个订阅

    await db.commit()

    return {
        "success_count": success_count,
        "failed_count": failed_count,
        "errors": errors
    }
```

---

## Performance Considerations / 性能考虑

### Optimization Strategies / 优化策略

1. **Batch Deletion / 批量删除**:
   - Use `delete().where()` with `in_()` clause for batch operations / 使用 `delete().where()` 和 `in_()` 子句进行批量操作
   - Avoid iterating and deleting one by one / 避免逐个迭代删除

2. **Database Indexes / 数据库索引**:
   - Ensure `subscriptions.id` is indexed / 确保 `subscriptions.id` 已索引
   - Ensure `podcast_episodes.subscription_id` is indexed / 确保 `podcast_episodes.subscription_id` 已索引

3. **Transaction Management / 事务管理**:
   - Use nested transactions (`begin_nested()`) for partial rollback support / 使用嵌套事务（`begin_nested()`）支持部分回滚
   - Limit batch size to 100 subscriptions per request / 限制每次请求最多 100 个订阅

### Performance Targets / 性能目标

| Metric / 指标 | Target / 目标 |
|---------------|---------------|
| Delete 10 subscriptions / 删除10个订阅 | < 2 seconds / 秒 |
| Delete 50 subscriptions / 删除50个订阅 | < 10 seconds / 秒 |
| Delete 100 subscriptions / 删除100个订阅 | < 20 seconds / 秒 |

---

## Testing / 测试

### Test Cases / 测试用例

#### 1. Normal Case / 正常情况

**Request / 请求**:
```json
{
  "subscription_ids": [1, 2, 3]
}
```

**Expected Response / 预期响应**:
```json
{
  "success_count": 3,
  "failed_count": 0,
  "errors": []
}
```

**Verification / 验证**:
- [ ] All 3 subscriptions are deleted from database / 数据库中所有3个订阅被删除
- [ ] All related episodes are deleted / 所有相关单集被删除
- [ ] All related conversations are deleted / 所有相关对话被删除
- [ ] All related transcription tasks are deleted / 所有相关转录任务被删除

#### 2. Partial Failure / 部分失败

**Request / 请求**:
```json
{
  "subscription_ids": [1, 999, 2]
}
```

**Expected Response / 预期响应**:
```json
{
  "success_count": 2,
  "failed_count": 1,
  "errors": [
    {
      "subscription_id": 999,
      "message": "Subscription not found or no permission"
    }
  ]
}
```

#### 3. Empty List / 空列表

**Request / 请求**:
```json
{
  "subscription_ids": []
}
```

**Expected Response / 预期响应**:
```json
{
  "detail": "Invalid request body"
}
```

**Status Code / 状态码**: 400 Bad Request

#### 4. Unauthorized / 未授权

**Request / 请求**:
```json
{
  "subscription_ids": [1]
}
```

**Headers / 请求头**: No Authorization header / 无 Authorization 头

**Expected Response / 预期响应**:
```json
{
  "detail": "Authentication required"
}
```

**Status Code / 状态码**: 401 Unauthorized

#### 5. Access Another User's Subscription / 访问其他用户订阅

**Request / 请求**:
```json
{
  "subscription_ids": [999]  # Belongs to another user / 属于其他用户
}
```

**Expected Response / 预期响应**:
```json
{
  "success_count": 0,
  "failed_count": 1,
  "errors": [
    {
      "subscription_id": 999,
      "message": "Subscription not found or no permission"
    }
  ]
}
```

---

## Security Considerations / 安全考虑

### Authorization / 授权

- **User Isolation / 用户隔离**: Users can only delete their own subscriptions / 用户只能删除自己的订阅
- **Ownership Verification / 所有权验证**: Verify each subscription belongs to the authenticated user / 验证每个订阅属于已认证用户

### Data Privacy / 数据隐私

- **Complete Deletion / 完整删除**: All related data must be deleted (GDPR compliance) / 必须删除所有相关数据（GDPR 合规）
- **No Soft Delete / 无软删除**: Data must be permanently removed from database / 数据必须从数据库中永久移除

### Audit Logging / 审计日志

```python
import logging

logger = logging.getLogger(__name__)

# Log deletion attempt
# 记录删除尝试
logger.info(
    f"Bulk delete attempt: user_id={user_id}, "
    f"subscription_ids={subscription_ids}, "
    f"success_count={success_count}, "
    f"failed_count={failed_count}"
)
```

---

## OpenAPI Specification / OpenAPI 规范

```yaml
/podcasts/subscriptions/bulk:
  delete:
    summary: Bulk delete podcast subscriptions
    description: Delete multiple podcast subscriptions and all related data
    tags:
      - Podcasts
    security:
      - BearerAuth: []
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required:
              - subscription_ids
            properties:
              subscription_ids:
                type: array
                items:
                  type: integer
                minItems: 1
                maxItems: 100
                example: [1, 2, 3, 4, 5]
    responses:
      '200':
        description: Deletion completed (may have partial failures)
        content:
          application/json:
            schema:
              type: object
              properties:
                success_count:
                  type: integer
                  minimum: 0
                  example: 4
                failed_count:
                  type: integer
                  minimum: 0
                  example: 1
                errors:
                  type: array
                  items:
                    type: object
                    properties:
                      subscription_id:
                        type: integer
                      message:
                        type: string
      '400':
        description: Invalid request body
        content:
          application/json:
            schema:
              type: object
              properties:
                detail:
                  type: string
      '401':
        description: Authentication required
        content:
          application/json:
            schema:
              type: object
              properties:
                detail:
                  type: string
      '403':
        description: No permission
        content:
          application/json:
            schema:
              type: object
              properties:
                detail:
                  type: string
      '500':
        description: Internal server error
        content:
          application/json:
            schema:
              type: object
              properties:
                detail:
                  type: string
```

---

## Frontend Integration / 前端集成

### Dart Repository Method / Dart Repository 方法

```dart
/// 批量删除播客订阅 / Bulk delete podcast subscriptions
///
/// [subscriptionIds] 要删除的订阅ID列表 / List of subscription IDs to delete
///
/// 返回删除结果 / Returns deletion result
///
/// 抛出 [DioException] 如果请求失败 / Throws [DioException] if request fails
Future<PodcastSubscriptionBulkDeleteResponse> deleteSubscriptionsBulk(
  List<int> subscriptionIds,
) async {
  try {
    final response = await _dio.delete(
      '/podcasts/subscriptions/bulk',
      data: {
        'subscription_ids': subscriptionIds,
      },
    );

    return PodcastSubscriptionBulkDeleteResponse.fromJson(response.data);
  } on DioException catch (e) {
    throw _handleError(e);
  }
}

/// 响应模型 / Response model
class PodcastSubscriptionBulkDeleteResponse {
  final int successCount;
  final int failedCount;
  final List<BulkDeleteError> errors;

  PodcastSubscriptionBulkDeleteResponse({
    required this.successCount,
    required this.failedCount,
    required this.errors,
  });

  factory PodcastSubscriptionBulkDeleteResponse.fromJson(Map<String, dynamic> json) {
    return PodcastSubscriptionBulkDeleteResponse(
      successCount: json['success_count'] as int,
      failedCount: json['failed_count'] as int,
      errors: (json['errors'] as List? ?? [])
          .map((e) => BulkDeleteError.fromJson(e as Map<String, dynamic>))
          .toList(),
    );
  }
}

class BulkDeleteError {
  final int subscriptionId;
  final String message;

  BulkDeleteError({
    required this.subscriptionId,
    required this.message,
  });

  factory BulkDeleteError.fromJson(Map<String, dynamic> json) {
    return BulkDeleteError(
      subscriptionId: json['subscription_id'] as int,
      message: json['message'] as String,
    );
  }
}
```

---

## Changelog / 变更日志

| Version / 版本 | Date / 日期 | Changes / 变更 | Author / 作者 |
|---------------|-------------|---------------|---------------|
| 1.0 | 2024-12-29 | Initial API contract definition / 初始 API 契约定义 | Product Manager |

---

**This API contract is part of FEP-20241229-001: Podcast Subscription Bulk Delete Feature**
**此 API 契约属于 FEP-20241229-001: 播客订阅批量删除功能**
