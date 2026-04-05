# Liquid Glass Redesign — Design Spec

> **Date:** 2026-04-05
> **Status:** Approved
> **Scope:** Full frontend UI redesign — all pages, all components
> **Approach:** Complete rewrite of existing glass system

## Decision Record

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Scope | Complete rewrite | Existing implementation has architectural debt; clean slate is faster than patching |
| Fidelity | Spirit match, technical adaptation | Flutter lacks Metal; capture Apple's principles within Flutter's capabilities |
| Color palette | Neutral background, glass as star | Apple HIG: Liquid Glass works best when background lets glass shine |
| Background | Dynamic gradient orbs | Gives glass something to refract/transmit, creating visual richness |
| Architecture | Composited widget system (BackdropFilter + CustomPaint) | Most compatible with Flutter, stable performance, maintainable |
| Coverage | All pages and components | Consistent experience across the entire app |

## 1. Rendering Pipeline

The glass effect is composed of 5 layers, rendered bottom-to-top:

```
Background Content (dynamic gradient orbs)
  ↓
Layer 1: Optical — BackdropFilter (gaussian blur + saturation boost via ColorFiltered)
Layer 2: Material — Container with semi-transparent fill, gradient border, outer shadow
Layer 3: Specular — CustomPainter: Fresnel rim light + moving specular highlight
Layer 4: Dynamic — CustomPainter: light flow animation + noise texture + tint overlay
Layer 5: Content — Child widget with padding and foreground color adaptation
```

**Key innovation vs existing implementation:**
- **Fresnel rim light** (Layer 3): Edge-gradient highlight — brighter at shallower angles, simulating real glass optics
- **Specular highlight** (Layer 3): Moving highlight point along glass surface via radial gradient
- **Programmatic noise** (Layer 4): dart:ui Canvas noise to avoid "plastic" look of pure fills

## 2. Glass Tier System

5 tiers with specific blur sigma and visual parameters:

| Tier | Sigma | Use Case | Interactive |
|------|-------|----------|-------------|
| ultraHeavy | 28 | Full-screen overlay, modal dialogs, expanded player | No |
| heavy | 20 | Bottom sheets, large panels, sidebar | No |
| medium | 14 | Navigation bar, tab bar, toolbar, search bar, mini player | No |
| light | 8 | Cards, list items, small panels, buttons, chips | Yes (hover/press) |

### Dark mode parameters (per tier)

| Param | ultraHeavy | heavy | medium | light |
|-------|-----------|-------|--------|-------|
| Fill (white %) | 4% | 5% | 6% | 7% |
| Border top (white %) | 8% | 10% | 13% | 16% |
| Border bottom (white %) | 4% | 5% | 7% | 8% |
| Inner glow (white %) | 3% | 4% | 5% | 6% |
| Shadow (black %) | 50% | 40% | 30% | 20% |
| Saturation boost | 2.0 | 1.8 | 1.5 | 1.3 |

### Light mode parameters (per tier)

| Param | ultraHeavy | heavy | medium | light |
|-------|-----------|-------|--------|-------|
| Fill (white %) | 60% | 55% | 50% | 45% |
| Border top (white %) | 70% | 65% | 60% | 55% |
| Border bottom (white %) | 40% | 35% | 30% | 25% |
| Inner glow (white %) | 15% | 14% | 12% | 10% |
| Shadow (black %) | 12% | 10% | 8% | 6% |
| Saturation boost | 1.2 | 1.2 | 1.15 | 1.1 |

## 3. Dynamic Background System

### Design
- **Dark mode:** Near-black base `#0A0A0F` with low-opacity (8-12%) indigo/violet/blue gradient orbs
- **Light mode:** Light gray base `#F0F0F5` with subtle (5-8%) color orbs

### Animation
- 3-5 radial gradient orbs, each drifting independently on a 30s cycle
- Easing: easeInOutSine, staggered start offsets
- Glass surface: 4s rotating specular highlight band, opacity 3-5%

### Color adaptation
Orb colors shift per page context:
- Podcast pages: indigo → violet
- Home: blue → cyan
- Settings/profile: neutral gray

### Performance
- 1 RepaintBoundary for the entire background
- Orbs use AnimatedContainer (not CustomPainter)
- Animations stop when page is not visible
- Low-end devices: static gradient fallback (no orb drift)

## 4. Interaction Animation System

### State transitions

| State | Duration | Curve | Visual change |
|-------|----------|-------|---------------|
| Default | — | — | Base tier values |
| Hover | 200ms | easeOut | σ+2, fill +3%, border brightness ×1.5, subtle indigo glow |
| Press | 150ms | easeIn | σ+4, scale ×0.98, shadow contracts |
| Entry | 400ms | easeOut | σ: 0→target, border opacity: 0→target, slight slide-up + fade-in. Plays once |

### Ambient animations
- **Light flow:** 4s cycle, rotating highlight band along glass surface, opacity 3-5%
- **Background orb drift:** 30s cycle, 3-5 orbs moving independently, staggered starts

### Page transitions
- **Route change:** New page slides in from bottom, old page shrinks + fades. 300ms, easeInOutCubic. Navigation bar stays stable.
- **Player expand:** Shared element transition from mini player position. Glass tier transitions Medium → Ultra Heavy. Blur sigma animates σ14 → σ28. Duration 400ms.

### Accessibility degradation
- **Reduce Motion:** Stop light flow and background drift. Only state transitions (hover/press) remain.
- **Reduce Transparency:** Fill opacity raised to 70%+, blur sigma reduced to σ4, approaching opaque panels.

## 5. Component → Tier Mapping

| Component | Tier | Interactive | Border Radius |
|-----------|------|-------------|---------------|
| Navigation bar / Tab bar | medium | No | Full width, no radius |
| Sidebar | heavy | No | Right-end radius 20 |
| Bottom Dock (mobile) | medium | No | 28px capsule |
| Podcast card | light | Yes (hover/press) | 22px |
| Daily report card | light | Yes (hover/press) | 16px |
| Highlight summary card | light | Yes (hover/press) | 22px |
| Expanded player | ultraHeavy | No | Top 28px |
| Mini player bar | medium | Yes (tap to expand) | 16px |
| Dialog / Bottom Sheet | heavy | No | Top 24px |
| Button / Chip | light | Yes (hover/press) | 12px |
| List items (scrolling) | static* | No | 12px |
| Calendar day cells | static* | No | 8px |

\* Static = semi-transparent fill color only, no BackdropFilter.

## 6. File Architecture

### New module: `core/glass/`

```
core/glass/
  glass_tokens.dart       — GlassTier enum, GlassTokens immutable class (all visual params per tier/brightness)
  glass_style.dart        — GlassStyle data class, factory forTier(), .withHover() / .withPress() modifiers
  glass_painter.dart      — CustomPainters: FresnelPainter, SpecularPainter, NoisePainter
  glass_container.dart    — GlassContainer widget (5-layer composition, AnimationController management)
  glass_background.dart   — GlassBackground widget (neutral base + drifting gradient orbs)
```

### Theme changes

- `app_colors.dart`: Remove `glassSurfaceStrong`, `glassShadow`, `glassBorder` from AppThemeExtension. Background colors change to `#0A0A0F` (dark) / `#F0F0F5` (light). Brand indigo retained as accent only.
- `app_theme.dart`: Add glass-styled component themes for Dialog, BottomSheet, AppBar, NavigationBar (transparent backgrounds, wrapped in GlassContainer).
- `theme_provider.dart`: No changes needed.

### Deleted files

- `core/theme/liquid_glass/` — entire directory
- `core/widgets/stella_background.dart` — replaced by GlassBackground

### Modified files

- `core/widgets/custom_adaptive_navigation.dart` — use new GlassContainer
- `core/widgets/app_shells.dart` — SurfacePanel uses new GlassContainer
- `features/podcast/presentation/widgets/highlight_card.dart`
- `features/podcast/presentation/pages/podcast_highlights_page.dart`
- `features/podcast/presentation/pages/podcast_daily_report_page.dart`
- `features/podcast/presentation/widgets/podcast_bottom_player_widget.dart` (and layouts file)
- `features/auth/` — all pages update references
- `features/settings/` — all pages update references
- `features/profile/` — all pages update references
- `features/home/` — all pages update references
- `features/splash/` — update references

## 7. Performance Constraints

| Constraint | Limit | Rationale |
|-----------|-------|-----------|
| BackdropFilter per screen | ≤ 3 | GPU-heavy; nav + player + 1 content panel |
| BackdropFilter in scrolling lists | 0 | Jank during scroll; use static semi-transparent |
| RepaintBoundary | Every GlassContainer | Isolate repaint from parent/siblings |
| Animation controllers | ≤ 2 per visible glass | Light flow + interaction state; entry plays once |
| Noise texture | Cached, 64×64, fixed seed | Generated once, reused across instances |

## 8. Migration Plan (4 Phases)

### Phase 1: Foundation — Tokens + Style + Background
- Create `core/glass/` module with GlassTokens, GlassStyle, GlassBackground
- Replace StellaBackground → GlassBackground (global effect)
- Clean AppThemeExtension: remove old glass tokens
- **Verification:** App launches with dynamic orb background

### Phase 2: Core — Painter + Container
- Implement FresnelPainter, SpecularPainter, NoisePainter
- Compose GlassContainer with 5-layer pipeline
- **Verification:** Demo page tests all tiers + interaction states

### Phase 3: Navigation + Player
- Migrate CustomAdaptiveNavigation (sidebar Heavy / dock Medium)
- Migrate mini player (Medium) + expanded player (Ultra Heavy)
- Update app_theme.dart component themes (Dialog, BottomSheet, AppBar)
- **Verification:** Navigation and player work with new glass, interactions smooth

### Phase 4: All Pages + Cleanup
- Migrate all remaining pages: cards, SurfacePanel, list items, settings, auth, profile, home
- Delete `core/theme/liquid_glass/` directory
- Delete `stella_background.dart`
- Update all import paths
- **Verification:** `flutter test` passes, no lingering old references

## 9. Apple HIG Compliance Checklist

- [x] Content is king — glass does not obscure content
- [x] Restraint — no glass-on-glass, max 3 BackdropFilter per screen
- [x] Hierarchy through material — navigation/controls use glass, content is opaque
- [x] Adaptability — dark/light mode with different parameters
- [x] Accessibility — Reduce Motion and Reduce Transparency support
- [x] Performance — RepaintBoundary isolation, scroll list optimization
- [x] Rounder forms matching hardware curvature — generous border radii
