# Podcast Shownotes HTML Rendering - Task Tracking / 播客 Shownotes HTML 渲染 - 任务跟踪

## Project Information / 项目信息

**English**:
- **Project Name**: Podcast Shownotes HTML Rendering Feature
- **Requirement ID**: REQ-20250103-001
- **Start Date**: 2025-01-03
- **Target Release**: 2025-01-17 (2 weeks)
- **Status**: Planning Phase

**中文**:
- **Project Name / 项目名称**: 播客 Shownotes HTML 渲染功能
- **Requirement ID / 需求ID**: REQ-20250103-001
- **Start Date / 开始日期**: 2025-01-03
- **Target Release / 目标发布**: 2025-01-17 (2周)
- **Status / 状态**: 规划阶段

---

## Overall Progress / 总体进度

**Phase 1: Research & Planning / 研究与规划** (100%)
- [x] Requirement analysis / 需求分析
- [x] Package evaluation / 包评估
- [x] Technical design / 技术设计
- [x] Task breakdown / 任务分解

**Phase 2: Development / 开发** (95% - COMPILATION ERRORS FIXED)
- [x] Backend implementation / 后端实现
- [x] Frontend implementation / 前端实现 (ALL COMPILATION ERRORS FIXED ✅)
- [ ] Integration / 集成 (READY FOR MANUAL TESTING)

**Phase 3: Testing / 测试** (20% - TEST FIXES NEEDED)
- [x] Unit tests / 单元测试 (WRITTEN, NEED TO VERIFY EXECUTION)
- [ ] Widget tests / Widget 测试 (NEED TEST ENVIRONMENT FIX)
- [ ] Integration tests / 集成测试 (READY FOR MANUAL TESTING)
- [ ] Performance tests / 性能测试
- [ ] Security tests / 安全测试

**Phase 4: Release / 发布** (10% - CONDITIONAL APPROVAL)
- [x] Code review / 代码审查 (CONDITIONALLY APPROVED - ALL COMPILATION ERRORS FIXED ✅)
- [x] Documentation / 文档 (COMPLETE)
- [ ] Deployment / 部署 (PENDING MANUAL TESTING)

---

## Task List / 任务列表

### Phase 1: Research & Planning / 研究与规划

#### TASK-001: Package Evaluation / 包评估
**English**:
- **Assigned To**: Product Manager + Frontend Developer
- **Estimated Time**: 2 hours
- **Status**: Todo
- **Priority**: Critical
- **Dependencies**: None

**Subtasks / 子任务**:
- [ ] Research `flutter_widget_from_html` package features
  - Use context7 to get official documentation
  - Check supported HTML tags and attributes
  - Verify platform compatibility
  - Review performance characteristics
- [ ] Research HTML sanitization libraries
  - Evaluate `html` package capabilities
  - Check XSS prevention features
  - Review custom tag allowlist options
- [ ] Document technical approach
  - Create architecture diagram
  - Define supported HTML elements
  - List security measures

**Acceptance Criteria / 验收标准**:
- [ ] Package evaluation document created
- [ ] Technical approach approved by architect
- [ ] No blockers for implementation

**中文**:
- **Assigned To / 负责人**: 产品经理 + 前端工程师
- **Estimated Time / 预估时间**: 2小时
- **Status / 状态**: 待办
- **Priority / 优先级**: 关键
- **Dependencies / 依赖**: 无

**Notes / 备注**:
- 使用 context7 获取 flutter_widget_from_html 官方文档
- 确认包的维护状态和社区支持

---

### Phase 2: Development / 开发

#### TASK-F-001: Add Dependencies / 添加依赖

**English**:
- **Assigned To**: Frontend Developer
- **Estimated Time**: 1 hour
- **Status**: Todo
- **Priority**: Critical
- **Dependencies**: TASK-001

**Subtasks / 子任务**:
- [ ] Update `frontend/pubspec.yaml`:
  ```yaml
  dependencies:
    flutter_widget_from_html: ^0.15.0
    cached_network_image: ^3.3.0
    html: ^0.15.0
  ```
- [ ] Run `flutter pub get`
- [ ] Verify no dependency conflicts
- [ ] Test imports in sample file

**Acceptance Criteria / 验收标准**:
- [ ] All dependencies added successfully
- [ ] `flutter pub get` completes without errors
- [ ] No version conflicts reported
- [ ] Sample import works

**中文**:
- **Assigned To / 负责人**: 前端工程师
- **Estimated Time / 预估时间**: 1小时
- **Status / 状态**: 待办
- **Priority / 优先级**: 关键
- **Dependencies / 依赖**: TASK-001

**Files to Modify / 需要修改的文件**:
- `frontend/pubspec.yaml`

---

#### TASK-F-002: Implement HTML Sanitizer / 实现 HTML 清理器

**English**:
- **Assigned To**: Frontend Developer
- **Estimated Time**: 4 hours
- **Status**: Todo
- **Priority**: Critical
- **Dependencies**: TASK-F-001

**Subtasks / 子任务**:
- [ ] Create utility class: `frontend/lib/shared/utils/html_sanitizer.dart`
- [ ] Implement tag allowlist:
  ```dart
  static const allowedTags = {
    'p', 'br', 'strong', 'em', 'b', 'i', 'u',
    'ul', 'ol', 'li', 'dl', 'dt', 'dd',
    'a', 'img',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'table', 'thead', 'tbody', 'tr', 'th', 'td',
    'blockquote', 'pre', 'code',
    'div', 'span',
  };
  ```
- [ ] Implement attribute allowlist:
  ```dart
  static const allowedAttributes = {
    'a': ['href', 'title'],
    'img': ['src', 'alt', 'width', 'height', 'title'],
    'td': ['colspan', 'rowspan'],
    'th': ['colspan', 'rowspan'],
  };
  ```
- [ ] Remove dangerous tags and event handlers
- [ ] Validate URL protocols
- [ ] Write unit tests (coverage > 90%)

**Acceptance Criteria / 验收标准**:
- [ ] HTML sanitizer class created
- [ ] All dangerous content removed
- [ ] Unit tests pass with > 90% coverage
- [ ] Security review passed

**中文**:
- **Assigned To / 负责人**: 前端工程师
- **Estimated Time / 预估时间**: 4小时
- **Status / 状态**: 待办
- **Priority / 优先级**: 关键
- **Dependencies / 依赖**: TASK-F-001

**Files to Create / 需要创建的文件**:
- `frontend/lib/shared/utils/html_sanitizer.dart`
- `frontend/test/unit/utils/html_sanitizer_test.dart`

---

#### TASK-F-003: Refactor ShownotesDisplayWidget / 重构 ShownotesDisplayWidget

**English**:
- **Assigned To**: Frontend Developer
- **Estimated Time**: 8 hours
- **Status**: Todo
- **Priority**: High
- **Dependencies**: TASK-F-002

**Subtasks / 子任务**:
- [ ] Replace custom parser with `HtmlWidget`
- [ ] Configure custom factory for Material 3 styling
- [ ] Implement dark/light mode support
- [ ] Add loading state UI
- [ ] Add error state UI
- [ ] Write widget tests

**Code Structure / 代码结构**:
```dart
class ShownotesDisplayWidget extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final shownotes = _getShownotesContent();

    if (shownotes.isEmpty) {
      return _buildEmptyState(context);
    }

    final sanitizedHtml = HtmlSanitizer.sanitize(shownotes);

    return SingleChildScrollView(
      child: HtmlWidget(
        sanitizedHtml,
        textStyle: Theme.of(context).textTheme.bodyLarge,
        customWidgetBuilder: _buildCustomWidget,
        onTapUrl: _handleUrlTap,
        factoryBuilder: () => MyWidgetFactory(),
      ),
    );
  }
}
```

**Acceptance Criteria / 验收标准**:
- [ ] Widget refactored to use HtmlWidget
- [ ] Material 3 theming applied
- [ ] Loading state displays correctly
- [ ] Error state handles gracefully
- [ ] Widget tests pass with > 80% coverage

**中文**:
- **Assigned To / 负责人**: 前端工程师
- **Estimated Time / 预估时间**: 8小时
- **Status / 状态**: 待办
- **Priority / 优先级**: 高
- **Dependencies / 依赖**: TASK-F-002

**Files to Modify / 需要修改的文件**:
- `frontend/lib/features/podcast/presentation/widgets/shownotes_display_widget.dart`
- `frontend/test/widget/podcast/shownotes_display_widget_test.dart`

---

#### TASK-F-004: Implement Image Handling / 实现图片处理

**English**:
- **Assigned To**: Frontend Developer
- **Estimated Time**: 6 hours
- **Status**: Todo
- **Priority**: High
- **Dependencies**: TASK-F-003

**Subtasks / 子任务**:
- [ ] Configure `cached_network_image` for HtmlWidget
- [ ] Set cache size limit (50MB)
- [ ] Implement placeholder widget
- [ ] Implement error widget
- [ ] Handle relative URLs
- [ ] Add max-width constraints
- [ ] Write widget tests

**Implementation Details / 实现细节**:
```dart
WidgetFactory buildImageWidget(String url, Map<String, String> attributes) {
  // Convert relative URLs to absolute
  final absoluteUrl = _makeAbsoluteUrl(url);

  return CachedNetworkImage(
    imageUrl: absoluteUrl,
    placeholder: (context, url) => _buildPlaceholder(),
    errorWidget: (context, url, error) => _buildErrorWidget(),
    maxWidth: context.width * 0.9,
    fit: BoxFit.contain,
  );
}
```

**Acceptance Criteria / 验收标准**:
- [ ] Images load and cache correctly
- [ ] Placeholder shows during loading
- [ ] Error widget shows on failure
- [ ] Relative URLs work
- [ ] Images are responsive
- [ ] Widget tests pass

**中文**:
- **Assigned To / 负责人**: 前端工程师
- **Estimated Time / 预估时间**: 6小时
- **Status / 状态**: 待办
- **Priority / 优先级**: 高
- **Dependencies / 依赖**: TASK-F-003

---

#### TASK-F-005: Implement Link Handling / 实现链接处理

**English**:
- **Assigned To**: Frontend Developer
- **Estimated Time**: 4 hours
- **Status**: Todo
- **Priority**: High
- **Dependencies**: TASK-F-003

**Subtasks / 子任务**:
- [ ] Implement tap handler for URLs
- [ ] Support different link types (http, https, mailto, tel)
- [ ] Add visual feedback (color, ripple)
- [ ] Show loading indicator
- [ ] Show error toast on failure
- [ ] Write widget tests

**Implementation Details / 实现细节**:
```dart
Future<void> _handleUrlTap(String url) async {
  final uri = Uri.parse(url);

  // Show loading indicator
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(content: CircularProgressIndicator()),
  );

  try {
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    } else {
      _showErrorToast('Cannot open link');
    }
  } catch (e) {
    _showErrorToast('Error opening link');
  }
}
```

**Acceptance Criteria / 验收标准**:
- [ ] HTTP/HTTPS links open in browser
- [ ] Mailto links open email client
- [ ] Tel links open dialer
- [ ] Visual feedback on tap
- [ ] Error handling works
- [ ] Widget tests pass

**中文**:
- **Assigned To / 负责人**: 前端工程师
- **Estimated Time / 预估时间**: 4小时
- **Status / 状态**: 待办
- **Priority / 优先级**: 高
- **Dependencies / 依赖**: TASK-F-003

---

#### TASK-F-006: Implement Responsive Layout / 实现响应式布局

**English**:
- **Assigned To**: Frontend Developer
- **Estimated Time**: 4 hours
- **Status**: Todo
- **Priority**: Medium
- **Dependencies**: TASK-F-003

**Subtasks / 子任务**:
- [ ] Implement responsive breakpoints
- [ ] Configure max content width
- [ ] Adjust padding for screen sizes
- [ ] Test on mobile, tablet, desktop
- [ ] Write widget tests

**Implementation Details / 实现细节**:
```dart
Widget _buildContent(BuildContext context, String html) {
  return LayoutBuilder(
    builder: (context, constraints) {
      final isDesktop = constraints.maxWidth > 840;
      final isTablet = constraints.maxWidth > 600;

      return Container(
        padding: EdgeInsets.symmetric(
          horizontal: isDesktop ? 32 : isTablet ? 24 : 16,
        ),
        constraints: BoxConstraints(
          maxWidth: isDesktop ? 800 : double.infinity,
        ),
        child: HtmlWidget(html),
      );
    },
  );
}
```

**Acceptance Criteria / 验收标准**:
- [ ] Content is responsive on all devices
- [ ] Max width enforced on desktop
- [ ] Padding appropriate for screen size
- [ ] Text wraps correctly
- [ ] Widget tests pass

**中文**:
- **Assigned To / 负责人**: 前端工程师
- **Estimated Time / 预估时间**: 4小时
- **Status / 状态**: 待办
- **Priority / 优先级**: 中
- **Dependencies / 依赖**: TASK-F-003

---

#### TASK-F-007: Accessibility Improvements / 可访问性改进

**English**:
- **Assigned To**: Frontend Developer
- **Estimated Time**: 3 hours
- **Status**: Todo
- **Priority**: Medium
- **Dependencies**: TASK-F-003

**Subtasks / 子任务**:
- [ ] Add semantic labels for images
- [ ] Add semantic labels for links
- [ ] Support system font scaling
- [ ] Ensure minimum touch targets (48x48dp)
- [ ] Test with screen reader
- [ ] Verify color contrast

**Acceptance Criteria / 验收标准**:
- [ ] Alt text provided for images
- [ ] Links have semantic labels
- [ ] Font scaling works
- [ ] Touch targets meet minimum size
- [ ] Screen reader test passed
- [ ] Color contrast WCAG AA compliant

**中文**:
- **Assigned To / 负责人**: 前端工程师
- **Estimated Time / 预估时间**: 3小时
- **Status / 状态**: 待办
- **Priority / 优先级**: 中
- **Dependencies / 依赖**: TASK-F-003

---

#### TASK-F-008: Performance Optimization / 性能优化

**English**:
- **Assigned To**: Frontend Developer
- **Estimated Time**: 4 hours
- **Status**: Todo
- **Priority**: Medium
- **Dependencies**: TASK-F-004, TASK-F-006

**Subtasks / 子任务**:
- [ ] Implement lazy rendering for long content
- [ ] Optimize image cache eviction
- [ ] Add performance monitoring
- [ ] Test with large HTML (> 100KB)
- [ ] Profile scroll performance
- [ ] Memory profiling

**Acceptance Criteria / 验收标准**:
- [ ] Initial render < 500ms
- [ ] Scroll FPS >= 60
- [ ] Memory usage reasonable
- [ ] Large files handled well

**中文**:
- **Assigned To / 负责人**: 前端工程师
- **Estimated Time / 预估时间**: 4小时
- **Status / 状态**: 待办
- **Priority / 优先级**: 中
- **Dependencies / 依赖**: TASK-F-004, TASK-F-006

---

### Backend Tasks / 后端任务

#### TASK-B-001: Verify API Response / 验证 API 响应

**English**:
- **Assigned To**: Backend Developer
- **Estimated Time**: 2 hours
- **Status**: Todo
- **Priority**: Medium
- **Dependencies**: None

**Subtasks / 子任务**:
- [ ] Check API response for description field
- [ ] Verify CDATA sections preserved
- [ ] Add logging for inspection
- [ ] Test with various podcast feeds

**Acceptance Criteria / 验收标准**:
- [ ] API returns full HTML content
- [ ] No HTML stripped on backend
- [ ] Logging added for debugging

**中文**:
- **Assigned To / 负责人**: 后端工程师
- **Estimated Time / 预估时间**: 2小时
- **Status / 状态**: 待办
- **Priority / 优先级**: 中
- **Dependencies / 依赖**: 无

---

### Phase 3: Testing / 测试

#### TASK-T-001: Unit Tests / 单元测试

**English**:
- **Assigned To**: Test Engineer
- **Estimated Time**: 6 hours
- **Status**: Todo
- **Priority**: High
- **Dependencies**: TASK-F-002, TASK-F-004, TASK-F-005

**Subtasks / 子任务**:
- [ ] Test HTML sanitization
- [ ] Test image URL handling
- [ ] Test link handling
- [ ] Test responsive layout
- [ ] Test error handling
- [ ] Achieve > 80% coverage

**Acceptance Criteria / 验收标准**:
- [ ] All unit tests pass
- [ ] Coverage > 80%
- [ ] Edge cases covered

**中文**:
- **Assigned To / 负责人**: 测试工程师
- **Estimated Time / 预估时间**: 6小时
- **Status / 状态**: 待办
- **Priority / 优先级**: 高
- **Dependencies / 依赖**: TASK-F-002, TASK-F-004, TASK-F-005

---

#### TASK-T-002: Widget Tests / Widget 测试

**English**:
- **Assigned To**: Test Engineer
- **Estimated Time**: 6 hours
- **Status**: Todo
- **Priority**: High
- **Dependencies**: TASK-F-003, TASK-F-004, TASK-F-005, TASK-F-006

**Subtasks / 子任务**:
- [ ] Test ShownotesDisplayWidget rendering
- [ ] Test loading states
- [ ] Test error states
- [ ] Test image loading
- [ ] Test link interactions
- [ ] Test responsive behavior
- [ ] Achieve > 80% coverage

**Acceptance Criteria / 验收标准**:
- [ ] All widget tests pass
- [ ] Coverage > 80%
- [ ] User flows covered

**中文**:
- **Assigned To / 负责人**: 测试工程师
- **Estimated Time / 预估时间**: 6小时
- **Status / 状态**: 待办
- **Priority / 优先级**: 高
- **Dependencies / 依赖**: TASK-F-003, TASK-F-004, TASK-F-005, TASK-F-006

---

#### TASK-T-003: Integration Tests / 集成测试

**English**:
- **Assigned To**: Test Engineer
- **Estimated Time**: 4 hours
- **Status**: Todo
- **Priority**: High
- **Dependencies**: TASK-T-001, TASK-T-002

**Subtasks / 子任务**:
- [ ] Test end-to-end shownotes display
- [ ] Test with 5 different podcast feeds
- [ ] Test navigation
- [ ] Test tab switching
- [ ] Test on multiple platforms

**Acceptance Criteria / 验收标准**:
- [ ] All integration tests pass
- [ ] Real feeds work correctly
- [ ] No platform-specific issues

**中文**:
- **Assigned To / 负责人**: 测试工程师
- **Estimated Time / 预估时间**: 4小时
- **Status / 状态**: 待办
- **Priority / 优先级**: 高
- **Dependencies / 依赖**: TASK-T-001, TASK-T-002

---

#### TASK-T-004: Performance Tests / 性能测试

**English**:
- **Assigned To**: Test Engineer
- **Estimated Time**: 3 hours
- **Status**: Todo
- **Priority**: Medium
- **Dependencies**: TASK-F-008

**Subtasks / 子任务**:
- [ ] Measure render time
- [ ] Measure scroll FPS
- [ ] Test memory usage
- [ ] Test with large HTML
- [ ] Generate report

**Acceptance Criteria / 验收标准**:
- [ ] Render time < 500ms
- [ ] Scroll FPS >= 60
- [ ] Memory usage reasonable
- [ ] Performance report created

**中文**:
- **Assigned To / 负责人**: 测试工程师
- **Estimated Time / 预估时间**: 3小时
- **Status / 状态**: 待办
- **Priority / 优先级**: 中
- **Dependencies / 依赖**: TASK-F-008

---

#### TASK-T-005: Security Tests / 安全测试

**English**:
- **Assigned To**: Test Engineer
- **Estimated Time**: 3 hours
- **Status**: Todo
- **Priority**: Critical
- **Dependencies**: TASK-F-002

**Subtasks / 子任务**:
- [ ] Test XSS prevention
- [ ] Test script tag injection
- [ ] Test javascript: URL injection
- [ ] Test iframe injection
- [ ] Verify event handlers removed
- [ ] Generate security report

**Acceptance Criteria / 验收标准**:
- [ ] All XSS attempts blocked
- [ ] No malicious content renders
- [ ] Security report created

**中文**:
- **Assigned To / 负责人**: 测试工程师
- **Estimated Time / 预估时间**: 3小时
- **Status / 状态**: 待办
- **Priority / 优先级**: 关键
- **Dependencies / 依赖**: TASK-F-002

---

## Timeline / 时间线

**Week 1 / 第1周** (2025-01-03 to 2025-01-10):
- Day 1-2: Research and package evaluation
- Day 3-5: Core implementation (sanitizer, widget refactoring)
- Day 6-7: Image and link handling

**Week 2 / 第2周** (2025-01-11 to 2025-01-17):
- Day 8-9: Responsive layout and accessibility
- Day 10: Performance optimization
- Day 11-13: Testing (unit, widget, integration)
- Day 14: Documentation and release

---

## Risk Tracking / 风险跟踪

| Risk / 风险 | Status / 状态 | Mitigation / 缓解措施 |
|------------|--------------|---------------------|
| Package doesn't support features / 包不支持功能 | ✅ Resolved | Simplified to use built-in HtmlWidget callbacks / 简化为使用内置 HtmlWidget 回调 |
| XSS vulnerabilities / XSS 漏洞 | ✅ Resolved | Comprehensive sanitization implemented / 实现了全面的清理 |
| Performance issues / 性能问题 | Monitoring | Performance testing needed / 需要性能测试 |
| Test environment setup issues / 测试环境设置问题 | ⚠️ Active | Fix localization in test setup / 修复测试设置中的本地化 |
| Timeline delay / 时间线延迟 | ⚠️ Minor | Manual testing can proceed / 手动测试可以继续 |

---

## Recent Updates / 最新更新

### 2025-01-03 - Re-verification Complete / 重新验收完成

**Status Change / 状态变更**: BLOCKED → CONDITIONALLY APPROVED

**Completed Actions / 完成的行动**:
- ✅ All compilation errors fixed (HTML sanitizer, WidgetFactory API, test parameters)
- ✅ Code analysis passes with no issues
- ✅ Re-verification report created

**Remaining Tasks / 剩余任务**:
- ⚠️ Fix test environment setup (add AppLocalizations to test widget)
- ⚠️ Manual testing with real podcast feeds
- ⚠️ Adjust test assertions based on actual HtmlWidget behavior

**Next Steps / 下一步**:
1. Manual testing with 5 different podcast feeds
2. Fix automated test setup
3. Final verification after manual testing passes

---

## Notes / 备注

**English**:
- Use context7 and exa MCP tools for research and documentation
- Follow Material 3 design guidelines
- Ensure bilingual support (Chinese/English)
- All code must follow project style guide
- Regular updates to this tracking document

**中文**:
- 使用 context7 和 exa MCP 工具进行研究和文档化
- 遵循 Material 3 设计指南
- 确保双语支持（中文/英文）
- 所有代码必须遵循项目风格指南
- 定期更新此跟踪文档

---

**Last Updated / 最后更新**: 2025-01-03
**Updated By / 更新人**: Product Manager
