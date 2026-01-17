# RSS订阅OPML导出功能需求文档

## 📋 需求概述 / Requirement Overview

### 需求标题 / Title
在Admin后台管理中添加RSS订阅OPML文件导出功能

### 优先级 / Priority
**P1 - 高优先级**

### 需求类型 / Type
功能增强 (Feature Enhancement)

---

## 🎯 用户故事 / User Story

### 中文
作为系统管理员，我希望能够在Admin后台管理页面一键导出所有RSS订阅到OPML文件，以便于：
- 备份现有的RSS订阅列表
- 在其他RSS阅读器中导入这些订阅
- 与其他管理员分享订阅配置

### English
As a system administrator, I want to export all RSS subscriptions to an OPML file from the admin panel, so that I can:
- Backup the existing RSS subscription list
- Import these subscriptions into other RSS readers
- Share subscription configuration with other administrators

---

## ✅ 验收标准 / Acceptance Criteria

### AC1: 后端API支持OPML导出
- [ ] 创建新的API端点：`GET /admin/api/subscriptions/export/opml`
- [ ] 返回标准OPML 2.0格式XML文件
- [ ] 文件名默认为 `stella.opml`
- [ ] 包含所有活跃状态的RSS订阅
- [ ] 每个订阅包含：title, xmlUrl, htmlUrl, description, category

### AC2: Admin页面添加导出按钮
- [ ] 在订阅管理页面 (`subscriptions.html`) 添加"导出OPML"按钮
- [ ] 按钮位置：页面顶部操作区域，与其他批量操作按钮并列
- [ ] 点击后触发浏览器下载 `stella.opml` 文件
- [ ] 按钮使用明显的图标和文字（中英文双语）

### AC3: OPML格式符合标准
- [ ] 生成的OPML文件符合OPML 2.0规范
- [ ] XML头部声明正确
- [ ] 包含`<opml>`根元素和`version="2.0"`属性
- [ ] 使用`<body>`和`<outline>`元素结构
- [ ] 支持分组：按category分组显示订阅

### AC4: 错误处理
- [ ] 当没有订阅时，返回空OPML结构（仅包含head元素）
- [ ] 处理数据库查询错误
- [ ] 记录导出操作到审计日志

### AC5: 权限控制
- [ ] 仅管理员可访问导出功能
- [ ] 验证管理员登录状态
- [ ] 审计日志记录操作用户

---

## 🔧 技术要求 / Technical Requirements

### 后端实现 (Backend)

#### 1. 新增API端点
**文件**: `backend/app/admin/router.py`

```python
@router.get("/api/subscriptions/export/opml")
async def export_subscriptions_opml(
    current_admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """导出所有RSS订阅为OPML文件"""
    # 实现逻辑
    pass
```

#### 2. OPML生成服务
**文件**: `backend/app/domains/subscription/services.py` (新增方法)

```python
async def generate_opml_content(
    self,
    db: AsyncSession,
    user_id: Optional[int] = None
) -> str:
    """生成OPML格式XML内容"""
    pass
```

#### 3. OPML格式要求
```xml
<?xml version="1.0" encoding="UTF-8"?>
<opml version="2.0">
  <head>
    <title>Stella RSS Subscriptions</title>
    <dateCreated>Tue, 17 Jan 2026 12:00:00 GMT</dateCreated>
    <ownerName>Stella Admin</ownerName>
  </head>
  <body>
    <!-- 按分类分组 -->
    <outline text="Tech" title="Tech">
      <outline text="Example Feed"
               xmlUrl="https://example.com/feed.xml"
               htmlUrl="https://example.com"
               description="Example description"/>
    </outline>
    <!-- 无分类的订阅 -->
    <outline text="Uncategorized Feed"
             xmlUrl="https://example2.com/feed.xml"
             htmlUrl="https://example2.com"/>
  </body>
</opml>
```

### 前端实现 (Frontend - Admin HTML)

#### 1. 添加导出按钮
**文件**: `backend/app/admin/templates/subscriptions.html`

```html
<!-- 在顶部操作区域添加 -->
<button onclick="exportOPML()"
        class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg flex items-center gap-2">
  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
          d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
  </svg>
  <span data-i18n="export_opml">导出 OPML / Export OPML</span>
</button>
```

#### 2. JavaScript函数
```javascript
async function exportOPML() {
  try {
    const response = await fetch('/admin/api/subscriptions/export/opml');
    if (!response.ok) throw new Error('Export failed');

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'stella.opml';
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  } catch (error) {
    console.error('Export error:', error);
    alert('导出失败 / Export failed');
  }
}
```

---

## 📊 数据模型 / Data Model

### Subscription Model (已存在)
```python
class Subscription(Base):
    id: int
    user_id: int
    title: str
    description: Optional[str]
    source_url: str  # RSS feed URL (对应OPML的xmlUrl)
    source_type: SubscriptionType
    status: SubscriptionStatus
    categories: List[SubscriptionCategory]  # 多对多关系
```

### OPML映射关系
| Subscription字段 | OPML元素 | 说明 |
|-----------------|----------|------|
| title | text/title | 订阅标题 |
| source_url | xmlUrl | RSS feed地址 |
| (从source_url解析) | htmlUrl | 网站主页URL |
| description | description | 订阅描述 |
| categories | outline嵌套 | 按分类分组 |

---

## 🧪 测试要求 / Testing Requirements

### 单元测试
- [ ] 测试OPML生成服务正确生成XML
- [ ] 测试空订阅列表返回空OPML
- [ ] 测试按category分组逻辑
- [ ] 测试特殊字符转义（XML转义）

### 集成测试
- [ ] 测试API端点返回正确的Content-Type (`application/xml`)
- [ ] 测试Content-Disposition头设置正确
- [ ] 测试权限验证（非管理员无法访问）

### 手动测试
- [ ] 在Admin页面点击导出按钮
- [ ] 验证下载的文件名为 `stella.opml`
- [ ] 用RSS阅读器（如Feedly）测试导入OPML文件
- [ ] 验证所有订阅信息完整

---

## 📝 API规范 / API Specification

### 端点信息
```
GET /admin/api/subscriptions/export/opml
```

### 请求头
```
Authorization: Bearer <admin_token>
```

### 响应
**成功** (200 OK):
```
Content-Type: application/xml; charset=utf-8
Content-Disposition: attachment; filename="stella.opml"

<OPML XML内容>
```

**错误** (401 Unauthorized):
```json
{
  "detail": "Not authenticated"
}
```

**错误** (403 Forbidden):
```json
{
  "detail": "Admin access required"
}
```

---

## 🎨 UI/UX设计要求 / UI/UX Requirements

### 按钮设计
- 位置：订阅管理页面顶部，与"批量刷新"按钮并列
- 颜色：绿色（表示导出/下载操作）
- 图标：下载图标（↓）
- 文字：中英文双语显示 "导出 OPML / Export OPML"

### 交互反馈
- 点击后显示"正在导出..."状态
- 下载完成后恢复按钮状态
- 出错时显示错误提示

---

## 📚 参考资源 / References

### OPML 2.0 规范
- 官方规范: http://www.opml.org/spec2
- 示例格式: https://dev.opml.org/spec2.html

### 相关代码
- 后端订阅服务: `backend/app/domains/subscription/services.py`
- Admin订阅页面: `backend/app/admin/templates/subscriptions.html`
- Admin路由: `backend/app/admin/router.py`

---

## 🚀 实施计划 / Implementation Plan

### 任务分解
1. **后端开发**
   - 在SubscriptionService中添加 `generate_opml_content` 方法
   - 在Admin router中添加 `/api/subscriptions/export/opml` 端点
   - 添加审计日志记录

2. **前端开发 (Admin HTML)**
   - 在subscriptions.html添加导出按钮
   - 实现exportOPML JavaScript函数
   - 添加加载状态和错误处理

3. **测试**
   - 编写单元测试
   - 手动测试导出功能
   - 验证OPML文件在第三方RSS阅读器中的兼容性

---

## 📌 额外说明 / Additional Notes

### MVP范围
- 本版本仅导出RSS类型的订阅（source_type = SubscriptionType.RSS）
- 仅导出ACTIVE状态的订阅
- 按category分组显示，未分类的订阅放在根级别

### 未来增强
- [ ] 支持选择特定订阅导出（通过复选框）
- [ ] 支持按日期范围导出
- [ ] 支持导出为JSON格式
- [ ] 支持导入OPML文件

### 兼容性
- 生成的OPML文件应与主流RSS阅读器兼容：
  - Feedly
  - Inoreader
  - NewsBlur
  - RSS Guard
  - Reeder

---

## 📅 创建信息 / Creation Info

- **创建日期 / Created**: 2026-01-17
- **需求负责人 / Product Owner**: Product Manager
- **技术负责人 / Tech Lead**: Backend Developer
- **状态 / Status**: 🟡 待实现 / Pending Implementation
