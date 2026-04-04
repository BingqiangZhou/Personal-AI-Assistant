import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import 'package:personal_ai_assistant/core/localization/app_localizations_extension.dart';
import 'package:personal_ai_assistant/core/theme/app_colors.dart';
import 'package:personal_ai_assistant/core/widgets/app_shells.dart';
import 'package:personal_ai_assistant/core/widgets/custom_adaptive_navigation.dart';
import 'package:personal_ai_assistant/shared/widgets/app_empty_state.dart';
import 'package:personal_ai_assistant/shared/widgets/stella_toast.dart';

/// AI tab page for Stella.
///
/// Provides a hub for AI-powered features including:
/// - Daily AI report summary
/// - Highlights overview
/// - Entry point to AI chat assistant (coming soon)
class AiTabPage extends StatefulWidget {
  const AiTabPage({super.key});

  @override
  State<AiTabPage> createState() => _AiTabPageState();
}

class _AiTabPageState extends State<AiTabPage> {
  bool _isLoading = false;

  final ScrollController _scrollController = ScrollController();

  final GlobalKey<RefreshIndicatorState> _refreshIndicatorKey =
      GlobalKey<RefreshIndicatorState>();

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<void> _loadData() async {
    if (!mounted) return;
    setState(() => _isLoading = false);
  }

  Future<void> _refresh() async {
    if (!mounted) return;
    setState(() => _isLoading = true);
    await _loadData();
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final width = MediaQuery.sizeOf(context).width;
    final isDesktop = width >= Breakpoints.large;

    return ContentShell(
      title: l10n.nav_ai,
      subtitle: l10n.ai_tab_subtitle,
      eyebrow: l10n.ai_tab_eyebrow,
      child: RefreshIndicator(
        key: _refreshIndicatorKey,
        onRefresh: _refresh,
        child: ListView(
          controller: _scrollController,
          padding: EdgeInsets.only(
            bottom: MediaQuery.viewPaddingOf(context).bottom + 24,
          children: [
            // Daily Report entry card
            _FeatureCard(
              icon: Icons.auto_awesome_outlined,
              title: l10n.podcast_daily_report_title,
              subtitle: l10n.ai_tab_daily_report_subtitle,
              onTap: () => context.go('/reports/daily'),
            ),
            const SizedBox(height: 12),
            // Highlights entry card
            _FeatureCard(
              icon: Icons.lightbulb_outline,
              title: l10n.podcast_highlights_title,
              subtitle: l10n.ai_tab_highlights_subtitle,
              onTap: () => context.go('/highlights'),
            ),
            const SizedBox(height: 12),
            // AI Assistant entry card (coming soon)
            _FeatureCard(
              icon: Icons.chat_bubble_outline,
              title: l10n.ai_tab_chat_title,
              subtitle: l10n.ai_tab_chat_subtitle,
              onTap: () {
                StellaToast.showToast(
                  context,
                  message: l10n.podcast_coming_soon,
                );
              },
            ),
            const SizedBox(height: 24),
          ],
        ),
      ),
    );
  }
}

/// Feature card for the AI tab page.
///
/// Displays a styled card with icon, title, subtitle, and an optional
/// onTap callback for navigation.
class _FeatureCard extends StatelessWidget {
  const _FeatureCard({
    super.key,
    required this.icon,
    required this.title,
    required this.subtitle,
    this.onTap,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback? onTap;
  static const double _cardHeight = 72.0;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final isDesktop = MediaQuery.sizeOf(context).width >= Breakpoints.large;

    return Semantics(
      button: true,
      label: title,
      child: Material(
        color: scheme.surface,
        borderRadius: BorderRadius.circular(16),
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(16),
          hoverColor: scheme.primary.withValues(alpha: 0.06),
          child: Padding(
            padding: EdgeInsets.symmetric(
              horizontal: 16,
              vertical: isDesktop ? 16 : 12,
            ),
            child: Row(
              children: [
                Container(
              width: 44,
              height: 44,
              decoration: BoxDecoration(
                color: scheme.primary.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Icon(icon, size: 22, color: scheme.primary),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    title,
                    style: theme.textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 2),
                  Text(
                    subtitle,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: scheme.onSurfaceVariant,
                    ),
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            const Spacer(),
            Icon(
              Icons.chevron_right,
              size: 18,
              color: scheme.onSurfaceVariant,
            ),
          ],
        ),
      ),
    ),
  }
}
