import 'dart:ui';

import 'package:flutter/material.dart';

import '../theme/app_colors.dart';
import 'custom_adaptive_navigation.dart';

MindriverThemeExtension mindriverThemeOf(BuildContext context) {
  return Theme.of(context).extension<MindriverThemeExtension>() ??
      (Theme.of(context).brightness == Brightness.dark
          ? MindriverThemeExtension.dark
          : MindriverThemeExtension.light);
}

class AppPageBackdrop extends StatelessWidget {
  const AppPageBackdrop({super.key, this.paddingTop = 0});

  final double paddingTop;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final tokens = mindriverThemeOf(context);

    return DecoratedBox(
      decoration: BoxDecoration(gradient: tokens.shellGradient),
      child: Stack(
        fit: StackFit.expand,
        children: [
          Positioned(
            top: paddingTop - 80,
            left: -40,
            child: _Orb(
              size: 220,
              color: tokens.heroGlow.withValues(alpha: 0.28),
            ),
          ),
          Positioned(
            top: paddingTop + 80,
            right: -60,
            child: _Orb(
              size: 200,
              color: theme.colorScheme.tertiary.withValues(alpha: 0.12),
            ),
          ),
          Positioned(
            bottom: -100,
            left: 40,
            child: _Orb(
              size: 240,
              color: theme.colorScheme.secondary.withValues(alpha: 0.08),
            ),
          ),
        ],
      ),
    );
  }
}

class _Orb extends StatelessWidget {
  const _Orb({required this.size, required this.color});

  final double size;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return IgnorePointer(
      child: ClipOval(
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: 12, sigmaY: 12),
          child: Container(
            width: size,
            height: size,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: RadialGradient(
                colors: [color, color.withValues(alpha: 0)],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class GlassPanel extends StatelessWidget {
  const GlassPanel({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(20),
    this.margin,
    this.borderRadius,
    this.backgroundColor,
    this.showHighlight = true,
  });

  final Widget child;
  final EdgeInsetsGeometry padding;
  final EdgeInsetsGeometry? margin;
  final double? borderRadius;
  final Color? backgroundColor;
  final bool showHighlight;

  @override
  Widget build(BuildContext context) {
    final tokens = mindriverThemeOf(context);
    final radius = borderRadius ?? tokens.cardRadius;

    return Container(
      margin: margin,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(radius),
        boxShadow: [
          BoxShadow(
            color: tokens.glassShadow,
            blurRadius: 32,
            offset: const Offset(0, 18),
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(radius),
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: 18, sigmaY: 18),
          child: Container(
            decoration: BoxDecoration(
              color: backgroundColor ?? tokens.glassSurface,
              borderRadius: BorderRadius.circular(radius),
              border: Border.all(color: tokens.glassBorder),
              gradient: showHighlight
                  ? LinearGradient(
                      colors: [
                        tokens.glassHighlight.withValues(alpha: 0.14),
                        Colors.transparent,
                      ],
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                    )
                  : null,
            ),
            padding: padding,
            child: child,
          ),
        ),
      ),
    );
  }
}

class StatusBadge extends StatelessWidget {
  const StatusBadge({super.key, required this.label, this.icon, this.color});

  final String label;
  final IconData? icon;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final resolvedColor = color ?? scheme.primary;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
      decoration: BoxDecoration(
        color: resolvedColor.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: resolvedColor.withValues(alpha: 0.18)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[
            Icon(icon, size: 13, color: resolvedColor),
            const SizedBox(width: 4),
          ],
          Text(
            label,
            style: Theme.of(context).textTheme.labelMedium?.copyWith(
              color: resolvedColor,
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }
}

class AppSectionHeader extends StatelessWidget {
  const AppSectionHeader({
    super.key,
    required this.title,
    this.subtitle,
    this.trailing,
  });

  final String title;
  final String? subtitle;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Row(
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title, style: theme.textTheme.titleLarge),
              if (subtitle != null) ...[
                const SizedBox(height: 4),
                Text(
                  subtitle!,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ],
          ),
        ),
        if (trailing != null) ...[const SizedBox(width: 16), trailing!],
      ],
    );
  }
}

class HeroHeader extends StatelessWidget {
  const HeroHeader({
    super.key,
    required this.title,
    required this.subtitle,
    this.eyebrow,
    this.leading,
    this.trailing,
    this.badges = const <Widget>[],
  });

  final String title;
  final String subtitle;
  final String? eyebrow;
  final Widget? leading;
  final Widget? trailing;
  final List<Widget> badges;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final tokens = mindriverThemeOf(context);
    final hasEyebrow = eyebrow != null && eyebrow!.trim().isNotEmpty;
    final hasSubtitle = subtitle.trim().isNotEmpty;
    final compactHeader = !hasEyebrow && !hasSubtitle && badges.isEmpty;

    return SizedBox(
      key: key,
      child: GlassPanel(
        padding: const EdgeInsets.fromLTRB(12, 12, 12, 12),
        borderRadius: tokens.panelRadius,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(
              height: compactHeader ? 72 : null,
              child: Row(
                crossAxisAlignment: compactHeader
                    ? CrossAxisAlignment.center
                    : CrossAxisAlignment.start,
                children: [
                  if (leading != null) ...[leading!, const SizedBox(width: 10)],
                  Expanded(
                    child: Column(
                      mainAxisAlignment: compactHeader
                          ? MainAxisAlignment.center
                          : MainAxisAlignment.start,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        if (hasEyebrow) ...[
                          Text(
                            eyebrow!,
                            style: theme.textTheme.labelMedium?.copyWith(
                              color: theme.colorScheme.primary,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                          const SizedBox(height: 4),
                        ],
                        Text(
                          title,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: compactHeader
                              ? theme.textTheme.headlineMedium
                              : theme.textTheme.headlineSmall,
                        ),
                        if (hasSubtitle) ...[
                          const SizedBox(height: 2),
                          Text(
                            subtitle,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: theme.colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),
                  if (trailing != null) ...[
                    const SizedBox(width: 10),
                    Align(
                      alignment: compactHeader
                          ? Alignment.center
                          : Alignment.topCenter,
                      child: trailing!,
                    ),
                  ],
                ],
              ),
            ),
            if (badges.isNotEmpty) ...[
              const SizedBox(height: 6),
              Wrap(spacing: 5, runSpacing: 5, children: badges),
            ],
          ],
        ),
      ),
    );
  }
}

class AppEmptyState extends StatelessWidget {
  const AppEmptyState({
    super.key,
    required this.icon,
    required this.title,
    this.subtitle,
    this.action,
  });

  final IconData icon;
  final String title;
  final String? subtitle;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;

    return Center(
      child: GlassPanel(
        padding: const EdgeInsets.all(28),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 420),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 72,
                height: 72,
                decoration: BoxDecoration(
                  color: scheme.primary.withValues(alpha: 0.12),
                  shape: BoxShape.circle,
                ),
                child: Icon(icon, size: 34, color: scheme.primary),
              ),
              const SizedBox(height: 18),
              Text(
                title,
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.titleLarge,
              ),
              if (subtitle != null) ...[
                const SizedBox(height: 8),
                Text(
                  subtitle!,
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: scheme.onSurfaceVariant,
                  ),
                ),
              ],
              if (action != null) ...[const SizedBox(height: 20), action!],
            ],
          ),
        ),
      ),
    );
  }
}

class ContentShell extends StatelessWidget {
  const ContentShell({
    super.key,
    required this.title,
    required this.subtitle,
    required this.child,
    this.eyebrow,
    this.leading,
    this.trailing,
    this.badges = const <Widget>[],
    this.headerSpacing = 8,
    this.maxWidth,
  });

  final String title;
  final String subtitle;
  final Widget child;
  final String? eyebrow;
  final Widget? leading;
  final Widget? trailing;
  final List<Widget> badges;
  final double headerSpacing;
  final double? maxWidth;

  @override
  Widget build(BuildContext context) {
    final tokens = mindriverThemeOf(context);

    return Material(
      color: Colors.transparent,
      child: Stack(
        fit: StackFit.expand,
        children: [
          const AppPageBackdrop(),
          ResponsiveContainer(
            maxWidth: maxWidth ?? tokens.contentMaxWidth,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                HeroHeader(
                  eyebrow: eyebrow,
                  title: title,
                  subtitle: subtitle,
                  leading: leading,
                  trailing: trailing,
                  badges: badges,
                ),
                SizedBox(height: headerSpacing),
                Expanded(child: child),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class ProfileShell extends StatelessWidget {
  const ProfileShell({
    super.key,
    required this.title,
    required this.subtitle,
    required this.summary,
    required this.child,
    this.trailing,
    this.badges = const <Widget>[],
  });

  final String title;
  final String subtitle;
  final Widget summary;
  final Widget child;
  final Widget? trailing;
  final List<Widget> badges;

  @override
  Widget build(BuildContext context) {
    final isMobile = MediaQuery.of(context).size.width < 600;
    final showSummary = summary is! SizedBox;
    final topSectionSpacing = isMobile ? 20.0 : 12.0;
    return Material(
      color: Colors.transparent,
      child: Stack(
        fit: StackFit.expand,
        children: [
          const AppPageBackdrop(),
          ResponsiveContainer(
            child: SingleChildScrollView(
              padding: const EdgeInsets.only(bottom: 24),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  HeroHeader(
                    key: const Key('profile_hero_header'),
                    title: title,
                    subtitle: subtitle,
                    trailing: trailing,
                    badges: badges,
                  ),
                  if (showSummary) ...[
                    SizedBox(height: topSectionSpacing),
                    summary,
                    const SizedBox(height: 12),
                  ],
                  if (!showSummary) SizedBox(height: topSectionSpacing),
                  child,
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class AuthShell extends StatelessWidget {
  const AuthShell({
    super.key,
    required this.title,
    required this.subtitle,
    required this.child,
    this.header,
    this.footer,
  });

  final String title;
  final String subtitle;
  final Widget child;
  final Widget? header;
  final Widget? footer;

  @override
  Widget build(BuildContext context) {
    final tokens = mindriverThemeOf(context);
    final width = MediaQuery.of(context).size.width;

    return Material(
      color: Colors.transparent,
      child: Stack(
        fit: StackFit.expand,
        children: [
          const AppPageBackdrop(),
          SafeArea(
            child: Center(
              child: SingleChildScrollView(
                padding: EdgeInsets.symmetric(
                  horizontal: width < 600 ? 20 : 32,
                  vertical: 24,
                ),
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 540),
                  child: Column(
                    children: [
                      if (header != null) ...[
                        header!,
                        const SizedBox(height: 18),
                      ],
                      GlassPanel(
                        padding: const EdgeInsets.fromLTRB(28, 28, 28, 28),
                        borderRadius: tokens.panelRadius,
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            Text(
                              title,
                              style: Theme.of(context).textTheme.headlineMedium,
                            ),
                            const SizedBox(height: 10),
                            Text(
                              subtitle,
                              style: Theme.of(context).textTheme.bodyMedium,
                            ),
                            const SizedBox(height: 24),
                            child,
                          ],
                        ),
                      ),
                      if (footer != null) ...[
                        const SizedBox(height: 18),
                        footer!,
                      ],
                    ],
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
