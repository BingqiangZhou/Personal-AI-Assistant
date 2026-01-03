# Floating Podcast Player Redesign Specification

## Overview / 概述

Redesign the podcast episode detail page player to use a floating widget on the right side of the screen instead of the bottom bar. The floating player has two states: collapsed (compact) and expanded (full controls).

重新设计播客详情页播放器，使用屏幕右侧的浮动控件替代底部播放栏。浮动播放器有两种状态：收起（紧凑）和展开（完整控件）。

---

## User Stories / 用户故事

### Primary User Story / 主要用户故事

**As a** podcast listener
**I want** a floating player on the right side of the episode detail page
**So that** I can control playback without obscuring the content

**作为**播客听众
**我想要**在详情页右侧有一个浮动播放器
**以便**在不遮挡内容的情况下控制播放

### Secondary User Stories / 次要用户故事

1. **Collapsed State**: Show a compact floating widget with expand button and play/pause control
   **收起状态**: 显示紧凑的浮动控件，包含展开按钮和播放/暂停控制

2. **Expanded State**: Show full player with progress, seek controls, and playback options
   **展开状态**: 显示完整播放器，包含进度、跳转控制和播放选项

3. **Smooth Transition**: Animate between collapsed and expanded states
   **平滑过渡**: 在收起和展开状态之间动画切换

---

## Functional Requirements / 功能需求

### FR1: Remove Bottom Player Bar / 移除底部播放栏

**Description / 描述**: Remove the current `_buildBottomPlayer` implementation from `PodcastEpisodeDetailPage`

**Acceptance Criteria / 验收标准**:
- [ ] Bottom player bar no longer appears on episode detail page
- [ ] Page content can use full screen height
- [ ] No visual artifacts or layout issues

---

### FR2: Floating Player - Collapsed State / 浮动播放器 - 收起状态

**Description / 描述**: Create a compact floating widget positioned on the right edge of the screen

**Visual Design / 视觉设计** (参考 Image 2):
```
┌────────────────────┐
│         ↑          │  <- Expand button (at top edge)
├────────────────────┤
│                    │
│      [Play]        │  <- Play/Pause button
│                    │
│  [Podcast Image]   │  <- Background image
│                    │
└────────────────────┘
```

**Layout Specifications / 布局规格**:
- **Position**: Right edge of screen, vertically centered
- **Width**: 64dp
- **Height**: Auto (approximately 200-240dp)
- **Border Radius**: 16dp
- **Elevation**: 8dp (floating effect)
- **Shadow**: Box shadow for depth

**Components / 组件**:
1. **Expand Button (展开按钮)**
   - Position: Top edge, horizontally centered
   - Icon: `Icons.expand_more` or similar
   - Size: 32x32dp
   - Background: Semi-transparent overlay
   - On tap: Expand to full player

2. **Play/Pause Button (播放/暂停按钮)**
   - Position: Below expand button, centered
   - Size: 48x48dp circular button
   - Icon: `Icons.play_arrow` / `Icons.pause`
   - Background: Semi-transparent overlay
   - On tap: Toggle playback

3. **Background (背景)**
   - Podcast cover image
   - Dark overlay (30% opacity) for icon contrast
   - Gradient fallback if no image

**Acceptance Criteria / 验收标准**:
- [ ] Floating widget appears on right side of screen
- [ ] Expand button at top edge
- [ ] Play/pause button below expand button
- [ ] Podcast image shows as background
- [ ] Smooth animation on expand/collapse
- [ ] Responsive positioning (mobile/desktop)

---

### FR3: Floating Player - Expanded State / 浮动播放器 - 展开状态

**Description / 描述**: Full-featured player with all controls

**Visual Design / 视觉设计** (参考 Image 1):
```
┌──────────────────────────────┐
│ 正在播放               [收起] │  <- Header
├──────────────────────────────┤
│ [Icon] Title                 │  <- Episode info
│        Date | Duration       │
├──────────────────────────────┤
│ ════════════════════════════ │  <- Progress bar
│ 00:05              -45:30    │  <- Time labels
├──────────────────────────────┤
│   [<10]  [Play]  [30>]      │  <- Playback controls
├──────────────────────────────┤
│   [倍速]  [列表] [睡眠]      │  <- Options
└──────────────────────────────┘
```

**Layout Specifications / 布局规格**:
- **Position**: Right edge of screen
- **Width**: 320dp (desktop), 280dp (tablet), full screen minus 32dp (mobile)
- **Max Height**: 80% of screen height
- **Border Radius**: 16dp
- **Elevation**: 12dp

**Components / 组件**:
1. **Header (顶部)**
   - Left: "正在播放" (Now Playing) text
   - Right: Collapse button (`Icons.expand_less`)

2. **Episode Info (单集信息)**
   - Podcast icon: 48x48dp
   - Title: 2 lines max, ellipsis
   - Publish date | Duration: Secondary text

3. **Progress Bar (进度条)**
   - Slider with theme color
   - Current time (left)
   - Remaining time (right, negative format)

4. **Playback Controls (播放控制)**
   - Rewind 10s: `< 10`
   - Play/Pause: Large circular button
   - Forward 30s: `30 >`

5. **Options Row (选项行)**
   - Playback speed selector: 0.5x - 3.0x
   - Playlist button: Show episode list
   - Sleep timer: Set sleep timer
   - (Download button - future implementation)

**Acceptance Criteria / 验收标准**:
- [ ] All controls are functional
- [ ] Smooth animation from collapsed state
- [ ] Progress bar updates in real-time
- [ ] Time labels show correct values
- [ ] Responsive layout for different screen sizes

---

### FR4: Animation & Transitions / 动画与过渡

**Description / 描述**: Smooth animations between states

**Specifications / 规格**:
- **Duration**: 300ms
- **Curve**: Curves.easeInOut
- **Properties**: Width, height, opacity, position

**Acceptance Criteria / 验收标准**:
- [ ] Collapse to expand: Smooth width/height transition
- [ ] Expand to collapse: Smooth width/height transition
- [ ] No janky animations (60fps)
- [ ] Icons animate with state change

---

## Technical Requirements / 技术需求

### TR1: Material 3 Compliance / Material 3 规范

- Use Material 3 design tokens
- Follow Material 3 color scheme
- Use Material 3 elevation system
- Support dark/light theme

### TR2: Responsive Design / 响应式设计

- **Desktop (>840dp)**: Fixed width 320dp, right edge positioning
- **Tablet (600-840dp)**: Fixed width 280dp, right edge positioning
- **Mobile (<600dp)**: Full width minus 32dp margins, or sheet from bottom

### TR3: State Management / 状态管理

- Use existing `AudioPlayerState` with `isExpanded` property
- Add `FloatingPlayerState` for collapsed/expanded tracking
- Connect to `audioPlayerProvider`

### TR4: Accessibility / 可访问性

- Semantic labels for all buttons
- Tooltip labels
- Keyboard navigation support
- Screen reader support

---

## Implementation Tasks / 实现任务

### Phase 1: Foundation / 基础阶段
- [ ] Create `FloatingPlayerController` for state management
- [ ] Create `CollapsedFloatingPlayerWidget` component
- [ ] Create `ExpandedFloatingPlayerWidget` component
- [ ] Remove bottom player from `PodcastEpisodeDetailPage`

### Phase 2: Integration / 集成阶段
- [ ] Add floating player to episode detail page
- [ ] Connect to audio player state
- [ ] Implement expand/collapse animations
- [ ] Test responsive layouts

### Phase 3: Polish / 完善阶段
- [ ] Add widget tests
- [ ] Verify accessibility
- [ ] Performance optimization
- [ ] End-to-end testing

---

## UI Mockups / UI 原型

### Collapsed State / 收起状态 (Image 2)
```
Screen Layout:
┌──────────────────────────────────────┐
│                                      │
│         Content Area                 │
│                                      │
│                            ┌────────┤
│                            │   ↑    │  <- Expand button
│                            ├────────┤
│                            │        │
│                            │  ▶️   │  <- Play/Pause
│                            │        │
│                            │ Image  │  <- Background
│                            │        │
│                            └────────┘
└──────────────────────────────────────┘
```

### Expanded State / 展开状态 (Image 1)
```
┌──────────────────────────────────────┐
│                                      │
│         Content Area         ┌───────┤
│                              │正在播放│
│                              ├───────┤
│                              │ [Icon]│
│                              │ Title │
│                              ├───────┤
│                              │ ═════ │  <- Progress
│                              │ 0:00  │
│                              ├───────┤
│                              │ [<▶️>]│
│                              ├───────┤
│                              │[×][≡]│
│                              └───────┘
└──────────────────────────────────────┘
```

---

## Success Metrics / 成功指标

1. **Usability**: Users can control playback without leaving content view
2. **Performance**: Animations run at 60fps
3. **Accessibility**: All controls are keyboard and screen reader accessible
4. **Responsiveness**: Works correctly on mobile, tablet, and desktop

---

## Dependencies / 依赖

- `flutter_riverpod`: State management
- `just_audio`: Audio playback (already in use)
- Material 3 components

## Related Files / 相关文件

- `frontend/lib/features/podcast/presentation/pages/podcast_episode_detail_page.dart`
- `frontend/lib/features/podcast/presentation/widgets/floating_player_widget.dart`
- `frontend/lib/features/podcast/presentation/widgets/audio_player_widget.dart`
- `frontend/lib/features/podcast/data/models/audio_player_state_model.dart`

---

**Status**: Draft / 草稿
**Created**: 2025-01-03
**Priority**: High / 高优先级
