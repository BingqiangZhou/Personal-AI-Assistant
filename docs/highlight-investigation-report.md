# 高亮点(Highlight)未生成问题调查报告

**调查日期:** 2026-03-21
**问题现象:** 一天过去了高亮点没有生成
**分析方法:** 代码审查 + 日志分析

---

## 📋 执行摘要

通过对代码的深入分析和日志排查，发现了**根本原因**：

### 🎯 根本原因（已确认）

**逻辑死循环**：在 `extract_pending_highlights` 批量处理流程中：

1. `_claim_pending_highlight_episode_ids` 将任务状态设为 `in_progress`
2. 然后调用 `extract_highlights_for_episode`
3. `extract_highlights_for_episode` 检查到 `in_progress` 就抛出 `ValidationError`
4. 任务被跳过，状态被重置为 `pending`
5. 下次运行又重复步骤 1-4

**日志证据:**
```
Skipping highlight extraction for episode 60486 due to unmet precondition: Highlight extraction already in progress for episode 60486
```

---

## 🔧 已应用的修复

### 修复 1: 添加分布式锁
- 新建 `backend/app/domains/podcast/tasks/handlers_highlight.py`
- 修改 `backend/app/domains/podcast/tasks/highlight_extraction.py` 使用新的 handler

### 修复 2: 修复 Session 管理
- 添加 `_reset_claimed_highlight_status_safe` 和 `_mark_highlight_extraction_failed_safe` 方法
- 异常处理使用独立 session (`worker_db_session`)

### 修复 3: 修复逻辑死循环（根本原因）
- 修改 `extract_highlights_for_episode` 中的 `in_progress` 检查逻辑
- 如果 `started_at` 超过1小时，视为僵尸任务，继续处理
- 如果是最近开始的（1小时内），则跳过（真正被其他 worker 持有）

**修复代码位置:** `backend/app/domains/podcast/services/highlight_extraction_service.py:626-643`

---

## 🔍 调度机制分析

### 定时任务配置
**文件:** `backend/app/core/celery_app.py:44-48`

```python
"extract-pending-highlights": {
    "task": "app.domains.podcast.tasks.highlight_extraction.extract_pending_highlights",
    "schedule": crontab(minute=15),  # 每小时15分执行
    "options": {"queue": "ai_generation"},
},
```

---

## 📝 修复验证步骤

### 1. 重启 Celery Worker
```bash
docker restart personal_ai_celery_worker_core
```

### 2. 检查日志
```bash
docker logs personal_ai_celery_worker_core --tail 100 | grep -i highlight
```

### 3. 手动触发测试（可选）
```bash
# 调用 API 手动触发
curl -X POST http://localhost:8000/api/v1/episodes/{episode_id}/highlights/extract
```

### 4. 检查数据库中的高亮点
```sql
SELECT
    COUNT(*) as total_highlights,
    COUNT(DISTINCT episode_id) as episodes_with_highlights
FROM episode_highlights
WHERE status = 'active';
```

---

## 📊 问题总结

| 问题 | 严重程度 | 状态 |
|------|---------|------|
| 逻辑死循环 | 🔴 严重 | ✅ 已修复 |
| 缺少分布式锁 | ⚠️ 中等 | ✅ 已修复 |
| Session 管理混乱 | ⚠️ 中等 | ✅ 已修复 |
| 行级锁范围不完整 | ⚠️ 低 | 未修改 (影响小) |

---

**报告生成时间:** 2026-03-21
