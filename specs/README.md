# Specs Index

Design specifications and implementation plans, organized by lifecycle status.

## Active

Current work-in-progress specs. Check here before implementing new features.

_(empty — no active specs)_

## Completed

| Date | Spec | Description |
|------|------|-------------|
| 2026-04-04 | [codebase-simplification](completed/2026-04-04-codebase-simplification-design.md) | Large-scale codebase simplification — all features retained, architecture streamlined |
| 2026-04-06 | [claudemd-rewrite](completed/2026-04-06-claudemd-rewrite-design.md) | Rewrite CLAUDE.md following Anthropic best practices |
| 2026-04-07 | [incremental-optimization](completed/2026-04-07-incremental-optimization-design.md) | Performance + reliability + security improvements across backend and frontend |
| 2026-04-15 | [remove-glass](completed/2026-04-15-remove-glass-design.md) | Remove glass effect, replace with flat Material 3 design |
| 2026-04-15 | [spacing-optimization](completed/2026-04-15-spacing-optimization-design.md) | Migrate all hardcoded spacing to AppSpacing 4-point grid tokens |
| 2026-04-16 | [platform-adaptive-ui](completed/2026-04-16-platform-adaptive-ui-design.md) | Replace pure Material 3 with platform-adaptive UI (Material/Cupertino) |
| 2026-04-16 | [ios-back-gesture](completed/2026-04-16-ios-back-gesture-design.md) | Fix iOS swipe-back gesture for all push-navigated pages |

## Superseded

These specs were replaced by newer versions. Kept for historical reference.

| Date | Spec | Superseded By |
|------|------|---------------|
| 2026-04-05 | [liquid-glass](superseded/2026-04-05-liquid-glass-design.md) | Monochrome Glass (2026-04-15) |
| 2026-04-15 | [monochrome-glass](superseded/2026-04-15-monochrome-glass-design.md) | Remove Glass (2026-04-15) |

## Naming Convention

- Design specs: `YYYY-MM-DD-<topic>-design.md`
- Implementation plans: `YYYY-MM-DD-<topic>-plan.md`
- Spec and plan files stay in the same directory
