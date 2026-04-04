# Liquid Glass Design Spec

**Date:** 2026-04-05
**Status:** Approved
**Scope:** Frontend global UI redesign — Apple Liquid Glass style

## Overview

将 Stella 前端的全部 UI 组件改造为 Apple Liquid Glass 风格，保留现有 Cosmic Editorial 配色体系。采用自定义 Widget 体系（方案 A），通过 BackdropFilter + 自定义装饰层 + 动画系统实现真实的玻璃质感。

### Design Goals

- 全局组件统一液态玻璃风格（导航栏、侧边栏、底部栏、卡片、对话框、按钮）
- 明暗双主题适配（深色模式效果明显，浅色模式更微妙）
- 全动态效果（光影流动、交互响应、入场动画、折射涟漪）
- 明显玻璃质感（重度模糊 + 饱和度提升 + Fresnel 边缘光）
- 性能可控（每屏最多 3 个 BackdropFilter，列表项不用实时模糊）

### Constraints

- 保留 Cosmic Editorial 配色（indigo-violet primary, cosmic dark theme）
- 不引入第三方玻璃效果包
- 遵循 Apple HIG：每屏最多 2-3 个 glass 元素，避免 glass-on-glass
- 列表中的 Card 不使用 BackdropFilter（性能）

## Architecture

### New Files

```
lib/core/theme/liquid_glass/
  liquid_glass_style.dart        # LiquidGlassStyle data class + LiquidGlassTier enum
  liquid_glass_container.dart    # Core widget (4-layer rendering + animations)
  liquid_glass_tokens.dart       # Theme token definitions
  liquid_glass_animations.dart   # Animation controllers
```

### Modified Files

| File | Change |
|------|--------|
| `app_colors.dart` | AppThemeExtension: add glass token fields |
| `app_theme.dart` | Component theme overrides for glass style |
| `custom_adaptive_navigation.dart` | `_CleanSidebar`, `_CleanDock` use LiquidGlassContainer |
| `app_shells.dart` | `SurfacePanel` uses LiquidGlassContainer |
| `stella_background.dart` | Enhanced gradient richness for better glass refraction |
| 5 feature files using legacy glass tokens | Replace with new LiquidGlass widget |

## Core Widget: LiquidGlassContainer

### Widget Interface

```dart
LiquidGlassContainer({
  required Widget child,
  LiquidGlassTier tier = LiquidGlassTier.medium,
  double? borderRadius,
  EdgeInsetsGeometry? padding,
  bool animate = true,
  bool interactive = true,
  Color? tint,
})
```

### 4-Layer Rendering Pipeline

**Layer 1: Optical (BackdropFilter)**
- Gaussian blur: `ImageFilter.blur(sigmaX: tier.sigma, sigmaY: tier.sigma)`
- Saturation boost: ColorFilter overlay at 180% (dark) / 130% (light)

**Layer 2: Material (Container decoration)**
- Semi-transparent fill: dark `white 5%` / light `white 45%`
- Gradient border (Fresnel): top `white 40%` → bottom `white 10%` (dark)
- Inner glow: `inset 0 0 0 1px rgba(255,255,255, 8%)`
- Soft shadow: `0 8px 32px rgba(0,0,0, 25%)` (dark)
- Noise texture: 2-3% monochromatic noise overlay

**Layer 3: Dynamic (AnimatedBuilder)**
- Light flow: rotating gradient sweep (3s cycle)
- Hover response: border light 40%→60%, blur +2, 200ms easeOut
- Press response: scale 0.98, blur +4, 150ms easeIn
- Selected: primary tint 15% overlay, glow enhancement, 250ms easeOut

**Layer 4: Content**
- Child widget rendered directly

### Glass Tier System

| Tier | Sigma | Components | Description |
|------|-------|-----------|-------------|
| `heavy` | 25 | Dialog, BottomSheet, Modal | Strong blur, highest optical density |
| `medium` | 18 | NavigationBar, SideRail, AppBar | Medium blur, navigation framework |
| `light` | 12 | Card, SurfacePanel | Light blur, content layer |
| `subtle` | 6 | Chip, Tooltip, Badge, Button | Minimal blur, accent elements |

### Light/Dark Mode Parameters

| Parameter | Dark Mode | Light Mode |
|-----------|-----------|------------|
| Fill | white 5% | white 45% |
| Border top | white 40% | white 60% |
| Border bottom | white 10% | white 30% |
| Inner glow | white 8% | white 12% |
| Shadow | black 25% | black 8% |
| Saturation boost | 180% | 130% |
| Light flow opacity | 3-6% | 2-4% |

## Component Adaptations

### 1. Bottom Dock (`_CleanDock`) — Tier: medium
- Wrap entire dock in LiquidGlassContainer
- Replace solid background + outline with glass material
- Enable light flow animation (ambient)
- Add refraction ripple on nav item tap
- Selected item: primary tint + glow

### 2. Sidebar (`_CleanSidebar`) — Tier: medium
- Wrap sidebar in LiquidGlassContainer
- Glass material replaces indigo-tinted solid surface
- Enable light flow animation
- Keep expand/collapse animation, enhance with glass blur transition
- Selected item: primary tint + amber dot indicator (keep existing)

### 3. Card / SurfacePanel — Tier: light
- SurfacePanel wraps content in LiquidGlassContainer
- **Only for fixed-position panels** (headers, standalone cards)
- Cards inside ListView/GridView: use static semi-transparent background + gradient border (no BackdropFilter)
- Keep existing fade-up entry animation

### 4. Dialog / BottomSheet — Tier: heavy
- Glass material with strongest blur
- Enable light flow and refraction ripple
- Entry: blur fades from 0 to target (400ms)
- Border light fades in (500ms)

### 5. AppBar — Tier: medium
- Transparent glass overlay on scrolled content
- Border light at bottom edge only
- Light flow animation enabled
- No glass when at page top (transparent, as current)

### 6. Buttons — Tier: subtle
- **Primary**: primary-tinted glass (indigo 30% fill + glass border + blur)
- **Outlined**: transparent glass with border light
- **Text**: no glass (keep flat)
- Refraction ripple on tap

## Animation System

### 1. Ambient Light Flow
- **What**: White gradient sweep moving across glass surface
- **How**: AnimatedBuilder driving LinearGradient rotation angle (0 → 2π)
- **Period**: 3 seconds, Curves.easeInOut
- **Overlay**: White 3-6% opacity diagonal gradient bar
- **Scope**: Navigation bar, sidebar, dock only (fixed-position components)

### 2. Interactive Response
- **Hover**: Border light 40%→60%, blur +2, 200ms easeOut
- **Press**: Scale 0.98, blur +4, 150ms easeIn
- **Selected**: Primary tint 15% overlay, glow enhancement, 250ms easeOut
- **Scope**: All interactive glass elements

### 3. Entry Animation
- **Framework layer** (sidebar/dock): Blur 0 → target (400ms), border light 0% → target (500ms), slide-in 8px (300ms)
- **Content layer** (card/dialog): Opacity 0 → 1 (200ms), slide-up 6px (200ms)

### 4. Refraction Ripple
- **What**: White ring expanding from tap point
- **How**: Custom Decoration + AnimationController
- **Duration**: 600ms, Curves.easeOut
- **Scope**: Buttons, nav items, tappable cards

## Theme Token Integration

New tokens added to `AppThemeExtension`:

```dart
// Liquid Glass Tokens
final double glassBlurHeavy;      // 25.0
final double glassBlurMedium;     // 18.0
final double glassBlurLight;      // 12.0
final double glassBlurSubtle;     // 6.0

final Color glassFill;            // light: white 45% / dark: white 5%
final Color glassBorderTop;       // light: white 60% / dark: white 40%
final Color glassBorderBottom;    // light: white 30% / dark: white 10%
final Color glassInnerGlow;       // light: white 12% / dark: white 8%
final Color glassShadow;          // light: black 8% / dark: black 25%

final double glassNoiseOpacity;   // 0.02-0.03
final int glassLightFlowDuration; // 3000ms
```

Existing `glassSurfaceStrong`, `glassShadow`, `glassBorder` tokens (legacy) will be replaced by the new token system.

## Performance Strategy

1. **RepaintBoundary isolation**: Each LiquidGlassContainer wraps its BackdropFilter area with RepaintBoundary to prevent cascading repaints
2. **Limit concurrent filters**: Max 3 BackdropFilter widgets per screen
3. **No blur in scrolling lists**: ListView/GridView items use static semi-transparent decoration (no BackdropFilter)
4. **Background caching**: StellaBackground is raster-cached via RepaintBoundary; static backgrounds don't trigger re-blur
5. **Animation offloading**: Light flow uses AnimatedBuilder (not setState), leverages Flutter's render pipeline optimization
6. **Platform awareness**: On low-end devices (detected via `MediaQuery.disableAnimations`), disable light flow and reduce blur sigma

## StellaBackground Enhancement

To provide richer colors for glass refraction:
- Dark mode: Add a subtle radial gradient accent (indigo 5%, violet 3%) behind content areas
- Light mode: Add warm gradient touches (amber 2%, violet 2%)
- These enhance the "vibrancy" effect when blurred through glass

## Legacy Token Migration

5 feature files currently reference `glassSurfaceStrong`, `glassShadow`, `glassBorder`:
- `podcast_highlights` related files
- `daily_report` related files
- `highlight_card` related files
- `bottom_player` related files

Each will be migrated to use `LiquidGlassContainer` with appropriate tier, replacing manual `glassSurfaceStrong.withValues(alpha: 0.96)` patterns.

## Out of Scope

- Routing, state management, network layer changes
- Business logic or data model changes
- Backend changes
- Third-party glass packages
- Web-specific fallbacks (target is desktop/mobile)
