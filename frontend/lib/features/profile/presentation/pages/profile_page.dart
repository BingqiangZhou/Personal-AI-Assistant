import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/localization/locale_provider.dart';
import 'package:personal_ai_assistant/core/theme/theme_provider.dart';
import 'package:personal_ai_assistant/core/widgets/top_floating_notice.dart';
import 'package:personal_ai_assistant/features/settings/presentation/widgets/update_dialog.dart';

import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../../../../shared/widgets/server_config_dialog.dart';
import '../../../auth/presentation/providers/auth_provider.dart';
import '../../../podcast/presentation/navigation/podcast_navigation.dart';
import '../../../podcast/presentation/providers/podcast_providers.dart';
import '../../../../core/utils/app_logger.dart' as logger;

/// Material Design 3自适应Profile页面
class ProfilePage extends ConsumerStatefulWidget {
  const ProfilePage({super.key});

  @override
  ConsumerState<ProfilePage> createState() => _ProfilePageState();
}

class _ProfilePageState extends ConsumerState<ProfilePage> {
  bool _notificationsEnabled = true;
  String _appVersion = 'Loading...';
  int _versionTapCount = 0;
  DateTime? _lastVersionTapAt;
  Timer? _versionTapTimer;

  static const Duration _versionTapWindow = Duration(milliseconds: 1200);

  @override
  void initState() {
    super.initState();
    _loadVersion();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref
          .read(podcastSubscriptionProvider.notifier)
          .loadSubscriptions()
          .catchError((_) {});
      ref.read(profileStatsProvider.notifier).load(forceRefresh: false);
      unawaited(
        ref
            .read(dailyReportDatesProvider.notifier)
            .load(forceRefresh: false)
            .catchError((_) => null),
      );
    });
  }

  @override
  void dispose() {
    _versionTapTimer?.cancel();
    super.dispose();
  }

  Future<void> _loadVersion() async {
    try {
      final packageInfo = await PackageInfo.fromPlatform();
      if (mounted) {
        setState(() {
          _appVersion = 'v${packageInfo.version} (${packageInfo.buildNumber})';
        });
      }
    } catch (e) {
      logger.AppLogger.debug('Error loading version: $e');
      if (mounted) {
        setState(() {
          _appVersion = 'Unknown';
        });
      }
    }
  }

  bool _isMobile(BuildContext context) =>
      MediaQuery.of(context).size.width < 600;

  double _dialogMaxWidth(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;
    return screenWidth < 600 ? screenWidth - 32 : 560.0;
  }

  EdgeInsets _dialogInsetPadding(BuildContext context) =>
      const EdgeInsets.all(16);

  EdgeInsetsGeometry _profileCardMargin(BuildContext context) =>
      _isMobile(context)
      ? const EdgeInsets.symmetric(horizontal: 4)
      : EdgeInsets.zero;

  ShapeBorder? _profileCardShape(BuildContext context) {
    if (!_isMobile(context)) {
      return null;
    }
    return RoundedRectangleBorder(
      borderRadius: BorderRadius.circular(12),
      side: BorderSide.none,
    );
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final authState = ref.watch(authProvider);
    final user = authState.user;

    return ResponsiveContainer(
      child: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // 页面标题和操作区域
            SizedBox(
              height: 56,
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      l10n.profile,
                      style: Theme.of(context).textTheme.headlineMedium
                          ?.copyWith(fontWeight: FontWeight.bold),
                    ),
                  ),
                  const SizedBox(width: 16),
                  PopupMenuButton<String>(
                    key: const Key('profile_user_menu_button'),
                    onSelected: (value) {
                      if (value == 'edit') {
                        _showEditProfileDialog(context);
                      } else if (value == 'logout') {
                        _showLogoutDialog(context);
                      }
                    },
                    offset: const Offset(0, 48),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                    itemBuilder: (context) => [
                      PopupMenuItem<String>(
                        enabled: false,
                        child: Row(
                          children: [
                            Icon(
                              Icons.person_outline,
                              size: 20,
                              color: Theme.of(
                                context,
                              ).colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Text(
                                user?.displayName ?? l10n.profile_guest_user,
                                style: Theme.of(context).textTheme.bodyMedium
                                    ?.copyWith(
                                      color: Theme.of(
                                        context,
                                      ).colorScheme.onSurface,
                                      fontWeight: FontWeight.w600,
                                    ),
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                          ],
                        ),
                      ),
                      PopupMenuItem<String>(
                        enabled: false,
                        child: Row(
                          children: [
                            Icon(
                              Icons.email_outlined,
                              size: 20,
                              color: Theme.of(
                                context,
                              ).colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Text(
                                user?.email ?? l10n.profile_please_login,
                                style: Theme.of(context).textTheme.bodyMedium
                                    ?.copyWith(
                                      color: Theme.of(
                                        context,
                                      ).colorScheme.onSurfaceVariant,
                                      fontWeight: FontWeight.w500,
                                    ),
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                          ],
                        ),
                      ),
                      const PopupMenuDivider(),
                      PopupMenuItem<String>(
                        value: 'edit',
                        key: const Key('profile_user_menu_item_edit'),
                        child: Row(
                          children: [
                            const Icon(Icons.edit_note, size: 20),
                            const SizedBox(width: 8),
                            Text(l10n.profile_edit_profile),
                          ],
                        ),
                      ),
                      PopupMenuItem<String>(
                        value: 'logout',
                        key: const Key('profile_user_menu_item_logout'),
                        child: Row(
                          children: [
                            Icon(
                              Icons.logout,
                              size: 20,
                              color: Theme.of(context).colorScheme.error,
                            ),
                            const SizedBox(width: 8),
                            Text(
                              l10n.logout,
                              style: TextStyle(
                                color: Theme.of(context).colorScheme.error,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                    child: CircleAvatar(
                      radius: 20,
                      backgroundColor: Theme.of(context).colorScheme.primary,
                      child: Text(
                        (user?.displayName ?? l10n.profile_guest_user)
                            .characters
                            .first
                            .toUpperCase(),
                        style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                          color: Theme.of(context).brightness == Brightness.dark
                              ? Colors.black
                              : Colors.white,
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 8),

            // 统计和活动卡片
            _buildActivityCards(context),

            const SizedBox(height: 8),

            // 设置选项
            _buildSettingsContent(context),

            // 底部空间
            const SizedBox(height: 16),
          ],
        ),
      ),
    );
  }

  /// 构建活动统计卡片
  Widget _buildActivityCards(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final isMobile = _isMobile(context);
    final statsAsync = ref.watch(profileStatsProvider);
    final subscriptionState = ref.watch(podcastSubscriptionProvider);
    final dailyReportDatesAsync = ref.watch(dailyReportDatesProvider);

    final episodeCount = statsAsync.when(
      data: (stats) => stats?.totalEpisodes.toString() ?? '0',
      loading: () => '...',
      error: (error, stackTrace) => '0',
    );
    final summaryCount = statsAsync.when(
      data: (stats) => stats?.summariesGenerated.toString() ?? '0',
      loading: () => '...',
      error: (error, stackTrace) => '0',
    );
    final historyCount = statsAsync.when(
      data: (stats) => stats?.playedEpisodes.toString() ?? '0',
      loading: () => '...',
      error: (error, stackTrace) => '0',
    );
    final subscriptionCount = subscriptionState.isLoading
        ? '...'
        : (subscriptionState.error != null
              ? '0'
              : subscriptionState.total.toString());
    final latestDailyReportDateText = dailyReportDatesAsync.when(
      data: (payload) {
        final dates = payload?.dates;
        if (dates == null || dates.isEmpty) {
          return '--';
        }
        return _formatDateOnly(dates.first.reportDate);
      },
      loading: () => '--',
      error: (error, stackTrace) => '--',
    );

    // On narrow screens, stack cards vertically to prevent squishing
    if (isMobile) {
      return Column(
        children: [
          _buildActivityCard(
            context,
            Icons.subscriptions_outlined,
            l10n.profile_subscriptions,
            subscriptionCount,
            Theme.of(context).colorScheme.primary,
            onTap: () => context.push('/profile/subscriptions'),
            showChevron: true,
          ),
          const SizedBox(height: 12),
          _buildActivityCard(
            context,
            Icons.podcasts,
            l10n.podcast_episodes,
            episodeCount,
            Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(height: 12),
          _buildActivityCard(
            context,
            Icons.auto_awesome,
            l10n.profile_ai_summary,
            summaryCount,
            Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(height: 12),
          _buildActivityCard(
            context,
            Icons.history,
            l10n.profile_viewed_title,
            historyCount,
            Theme.of(context).colorScheme.secondary,
            onTap: () => context.push('/profile/history'),
            showChevron: true,
            chevronKey: const Key('profile_viewed_card_chevron'),
          ),
          const SizedBox(height: 12),
          _buildActivityCard(
            context,
            Icons.summarize_outlined,
            l10n.podcast_daily_report_title,
            latestDailyReportDateText,
            Theme.of(context).colorScheme.primary,
            onTap: () =>
                PodcastNavigation.goToDailyReport(context, source: 'profile'),
            showChevron: true,
            cardKey: const Key('profile_daily_report_card'),
          ),
        ],
      );
    }

    return LayoutBuilder(
      builder: (context, constraints) {
        final maxWidth = constraints.maxWidth;
        final columns = maxWidth >= 1000 ? 4 : 2;
        final cardWidth = (maxWidth - (columns - 1) * 16) / columns;

        final cards = <Widget>[
          _buildActivityCard(
            context,
            Icons.subscriptions_outlined,
            l10n.profile_subscriptions,
            subscriptionCount,
            Theme.of(context).colorScheme.primary,
            onTap: () => context.push('/profile/subscriptions'),
            showChevron: true,
          ),
          _buildActivityCard(
            context,
            Icons.podcasts,
            l10n.podcast_episodes,
            episodeCount,
            Theme.of(context).colorScheme.primary,
          ),
          _buildActivityCard(
            context,
            Icons.auto_awesome,
            l10n.profile_ai_summary,
            summaryCount,
            Theme.of(context).colorScheme.primary,
          ),
          _buildActivityCard(
            context,
            Icons.history,
            l10n.profile_viewed_title,
            historyCount,
            Theme.of(context).colorScheme.secondary,
            onTap: () => context.push('/profile/history'),
            showChevron: true,
            chevronKey: const Key('profile_viewed_card_chevron'),
          ),
          _buildActivityCard(
            context,
            Icons.summarize_outlined,
            l10n.podcast_daily_report_title,
            latestDailyReportDateText,
            Theme.of(context).colorScheme.primary,
            onTap: () =>
                PodcastNavigation.goToDailyReport(context, source: 'profile'),
            showChevron: true,
            cardKey: const Key('profile_daily_report_card'),
          ),
        ];

        return Wrap(
          spacing: 16,
          runSpacing: 16,
          children: [
            for (final card in cards) SizedBox(width: cardWidth, child: card),
          ],
        );
      },
    );
  }

  Widget _buildActivityCard(
    BuildContext context,
    IconData icon,
    String label,
    String value,
    Color color, {
    VoidCallback? onTap,
    bool showChevron = false,
    Key? chevronKey,
    Key? cardKey,
  }) {
    final effectiveIconColor = _ensureIconContrast(context, color);
    return Card(
      key: cardKey,
      margin: _profileCardMargin(context),
      shape: _profileCardShape(context),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              Icon(icon, color: effectiveIconColor, size: 24),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      label,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      value,
                      style: Theme.of(context).textTheme.headlineSmall
                          ?.copyWith(fontWeight: FontWeight.bold),
                    ),
                  ],
                ),
              ),
              if (showChevron)
                Icon(
                  Icons.chevron_right,
                  key: chevronKey,
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                  size: 22,
                ),
            ],
          ),
        ),
      ),
    );
  }

  Color _ensureIconContrast(BuildContext context, Color proposed) {
    final scheme = Theme.of(context).colorScheme;
    final cardColor = Theme.of(context).cardTheme.color ?? scheme.surface;
    final diff = (proposed.computeLuminance() - cardColor.computeLuminance())
        .abs();
    if (diff < 0.25) {
      return scheme.onSurfaceVariant;
    }
    return proposed;
  }

  String _formatDateOnly(DateTime value) {
    final local = value.isUtc ? value.toLocal() : value;
    return '${local.year.toString().padLeft(4, '0')}-${local.month.toString().padLeft(2, '0')}-${local.day.toString().padLeft(2, '0')}';
  }

  /// 构建设置内容
  Widget _buildSettingsContent(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final screenWidth = MediaQuery.of(context).size.width;
    final isMobile = screenWidth < 600;

    if (isMobile) {
      return Column(
        children: [
          _buildSettingsSection(context, l10n.profile_account_settings, [
            _buildSettingsItem(
              context,
              icon: Icons.shield,
              title: l10n.profile_security,
              subtitle: l10n.profile_security_subtitle,
              onTap: () => _showSecurityDialog(context),
            ),
            _buildSettingsItem(
              context,
              icon: Icons.notifications,
              title: l10n.profile_notifications,
              subtitle: l10n.profile_notifications_subtitle,
              trailing: Switch(
                value: _notificationsEnabled,
                onChanged: (value) {
                  setState(() {
                    _notificationsEnabled = value;
                  });
                },
              ),
            ),
          ]),
          const SizedBox(height: 24),
          _buildSettingsSection(context, l10n.preferences, [
            Consumer(
              builder: (context, ref, _) {
                final localeNotifier = ref.watch(localeProvider.notifier);
                final currentCode = localeNotifier.languageCode;
                final l10n = AppLocalizations.of(context)!;

                String languageName;
                if (currentCode == kLanguageSystem) {
                  languageName = l10n.languageFollowSystem;
                } else if (currentCode == kLanguageChinese) {
                  languageName = l10n.languageChinese;
                } else {
                  languageName = l10n.languageEnglish;
                }

                return _buildSettingsItem(
                  context,
                  icon: Icons.language,
                  title: l10n.language,
                  subtitle: languageName,
                  onTap: () => _showLanguageDialog(context),
                );
              },
            ),
            Consumer(
              builder: (context, ref, _) {
                final themeNotifier = ref.watch(themeModeProvider.notifier);
                final currentCode = themeNotifier.themeModeCode;

                String themeModeName;
                if (currentCode == kThemeModeSystem) {
                  themeModeName = l10n.theme_mode_follow_system;
                } else if (currentCode == kThemeModeLight) {
                  themeModeName = l10n.theme_mode_light;
                } else {
                  themeModeName = l10n.theme_mode_dark;
                }

                return _buildSettingsItem(
                  context,
                  icon: Icons.dark_mode,
                  title: l10n.theme_mode,
                  subtitle: themeModeName,
                  onTap: () => _showThemeModeDialog(context),
                );
              },
            ),
          ]),
          const SizedBox(height: 24),
          _buildSettingsSection(context, l10n.profile_support_section, [
            _buildSettingsItem(
              context,
              icon: Icons.help,
              title: l10n.profile_help_center,
              subtitle: l10n.profile_help_center_subtitle,
              onTap: () => _showHelpDialog(context),
            ),
            _buildSettingsItem(
              context,
              icon: Icons.cleaning_services,
              title: l10n.profile_cache_management,
              subtitle: l10n.profile_cache_management_subtitle,
              tileKey: const Key('profile_clear_cache_item'),
              onTap: () => context.push('/profile/cache'),
            ),
          ]),
          const SizedBox(height: 24),
          _buildSettingsSection(context, l10n.about, [
            _buildSettingsItem(
              context,
              icon: Icons.system_update_alt,
              title: l10n.update_check_updates,
              subtitle: l10n.update_auto_check,
              trailing: const Icon(Icons.chevron_right),
              onTap: () => _showUpdateCheckDialog(context),
            ),
            _buildSettingsItem(
              context,
              icon: Icons.info_outline,
              title: l10n.version,
              subtitle: _getVersionSubtitle(),
              trailing: const Icon(Icons.chevron_right),
              tileKey: const Key('profile_version_item'),
              onTap: () => _handleVersionTap(context),
            ),
          ]),
        ],
      );
    } else {
      // 桌面端两列布局，优化间距和布局
      return Column(
        children: [
          Row(
            children: [
              Expanded(
                child: Column(
                  children: [
                    _buildSettingsSection(
                      context,
                      l10n.profile_account_settings,
                      [
                        _buildSettingsItem(
                          context,
                          icon: Icons.shield,
                          title: l10n.profile_security,
                          subtitle: l10n.profile_security_subtitle,
                          onTap: () => _showSecurityDialog(context),
                        ),
                        _buildSettingsItem(
                          context,
                          icon: Icons.notifications,
                          title: l10n.profile_notifications,
                          subtitle: l10n.profile_notifications_subtitle,
                          trailing: Switch(
                            value: _notificationsEnabled,
                            onChanged: (value) {
                              setState(() {
                                _notificationsEnabled = value;
                              });
                            },
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  children: [
                    _buildSettingsSection(context, l10n.preferences, [
                      Consumer(
                        builder: (context, ref, _) {
                          final localeNotifier = ref.watch(
                            localeProvider.notifier,
                          );
                          final currentCode = localeNotifier.languageCode;
                          final l10n = AppLocalizations.of(context)!;

                          String languageName;
                          if (currentCode == kLanguageSystem) {
                            languageName = l10n.languageFollowSystem;
                          } else if (currentCode == kLanguageChinese) {
                            languageName = l10n.languageChinese;
                          } else {
                            languageName = l10n.languageEnglish;
                          }

                          return _buildSettingsItem(
                            context,
                            icon: Icons.language,
                            title: l10n.language,
                            subtitle: languageName,
                            onTap: () => _showLanguageDialog(context),
                          );
                        },
                      ),
                      Consumer(
                        builder: (context, ref, _) {
                          final themeNotifier = ref.watch(
                            themeModeProvider.notifier,
                          );
                          final currentCode = themeNotifier.themeModeCode;
                          final l10n = AppLocalizations.of(context)!;

                          String themeModeName;
                          if (currentCode == kThemeModeSystem) {
                            themeModeName = l10n.theme_mode_follow_system;
                          } else if (currentCode == kThemeModeLight) {
                            themeModeName = l10n.theme_mode_light;
                          } else {
                            themeModeName = l10n.theme_mode_dark;
                          }

                          return _buildSettingsItem(
                            context,
                            icon: Icons.dark_mode,
                            title: l10n.theme_mode,
                            subtitle: themeModeName,
                            onTap: () => _showThemeModeDialog(context),
                          );
                        },
                      ),
                    ]),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 24),
          _buildSettingsSection(context, l10n.profile_support_section, [
            _buildSettingsItem(
              context,
              icon: Icons.help,
              title: l10n.profile_help_center,
              subtitle: l10n.profile_help_center_subtitle,
              onTap: () => _showHelpDialog(context),
            ),
            _buildSettingsItem(
              context,
              icon: Icons.cleaning_services,
              title: l10n.profile_cache_management,
              subtitle: l10n.profile_cache_management_subtitle,
              tileKey: const Key('profile_clear_cache_item'),
              onTap: () => context.push('/profile/cache'),
            ),
          ]),
          const SizedBox(height: 24),
          _buildSettingsSection(context, l10n.about, [
            _buildSettingsItem(
              context,
              icon: Icons.system_update_alt,
              title: l10n.update_check_updates,
              subtitle: l10n.update_auto_check,
              trailing: const Icon(Icons.chevron_right),
              onTap: () => _showUpdateCheckDialog(context),
            ),
            _buildSettingsItem(
              context,
              icon: Icons.info_outline,
              title: l10n.version,
              subtitle: _getVersionSubtitle(),
              trailing: const Icon(Icons.chevron_right),
              tileKey: const Key('profile_version_item'),
              onTap: () => _handleVersionTap(context),
            ),
          ]),
        ],
      );
    }
  }

  /// 统一的 Card 样式封装，确保所有卡片 margin 一致
  // 保留此方法以便将来统一使用，目前所有卡片已手动设置 margin: EdgeInsets.zero
  // ignore: unused_element
  Widget _buildCard(Widget child) =>
      Card(margin: EdgeInsets.zero, child: child);

  /// 构建设置分组
  Widget _buildSettingsSection(
    BuildContext context,
    String title,
    List<Widget> children,
  ) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.only(top: 8, bottom: 8),
          child: Text(
            title,
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.bold,
              color: Theme.of(context).colorScheme.onSurface,
            ),
          ),
        ),
        Card(
          margin: _profileCardMargin(context),
          shape: _profileCardShape(context),
          child: Column(children: children),
        ),
      ],
    );
  }

  /// 构建设置项目
  Widget _buildSettingsItem(
    BuildContext context, {
    Key? tileKey,
    required IconData icon,
    required String title,
    required String subtitle,
    Widget? trailing,
    VoidCallback? onTap,
  }) {
    return ListTile(
      key: tileKey,
      leading: Icon(icon),
      title: Text(title),
      subtitle: Text(subtitle),
      trailing: trailing ?? const Icon(Icons.chevron_right),
      onTap: onTap,
    );
  }

  /// 显示编辑个人资料对话框
  void _showEditProfileDialog(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    showDialog(
      context: context,
      builder: (context) => LayoutBuilder(
        builder: (context, constraints) {
          return ConstrainedBox(
            constraints: BoxConstraints(maxWidth: _dialogMaxWidth(context)),
            child: AlertDialog(
              insetPadding: _dialogInsetPadding(context),
              title: Text(l10n.profile_edit_profile),
              content: SizedBox(
                width: double.maxFinite,
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    TextField(
                      decoration: InputDecoration(
                        labelText: l10n.profile_name,
                        border: const OutlineInputBorder(),
                      ),
                    ),
                    const SizedBox(height: 16),
                    TextField(
                      decoration: InputDecoration(
                        labelText: l10n.profile_email_field,
                        border: const OutlineInputBorder(),
                      ),
                    ),
                    const SizedBox(height: 16),
                    TextField(
                      decoration: InputDecoration(
                        labelText: l10n.profile_bio,
                        border: const OutlineInputBorder(),
                      ),
                      maxLines: 3,
                    ),
                  ],
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: Text(l10n.cancel),
                ),
                FilledButton(
                  onPressed: () {
                    Navigator.of(context).pop();
                    showTopFloatingNotice(
                      context,
                      message: l10n.profile_updated_successfully,
                    );
                  },
                  child: Text(l10n.save),
                ),
              ],
            ),
          );
        },
      ),
    );
  }

  /// 显示安全对话框
  void _showSecurityDialog(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    showDialog(
      context: context,
      builder: (context) => LayoutBuilder(
        builder: (context, constraints) {
          return ConstrainedBox(
            constraints: BoxConstraints(maxWidth: _dialogMaxWidth(context)),
            child: AlertDialog(
              insetPadding: _dialogInsetPadding(context),
              title: Text(l10n.profile_security),
              content: SizedBox(
                width: double.maxFinite,
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    ListTile(
                      leading: const Icon(Icons.password),
                      title: Text(l10n.profile_change_password),
                      trailing: const Icon(Icons.chevron_right),
                    ),
                    ListTile(
                      leading: const Icon(Icons.fingerprint),
                      title: Text(l10n.profile_biometric_auth),
                      trailing: Switch(value: true, onChanged: null),
                    ),
                    ListTile(
                      leading: const Icon(Icons.phone_android),
                      title: Text(l10n.profile_two_factor_auth),
                      trailing: const Icon(Icons.chevron_right),
                    ),
                  ],
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: Text(l10n.close),
                ),
              ],
            ),
          );
        },
      ),
    );
  }

  /// 显示语言对话框
  void _showLanguageDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => LayoutBuilder(
        builder: (context, constraints) {
          return ConstrainedBox(
            constraints: BoxConstraints(maxWidth: _dialogMaxWidth(context)),
            child: Consumer(
              builder: (context, ref, _) {
                final localeNotifier = ref.watch(localeProvider.notifier);
                final currentCode = localeNotifier.languageCode;
                final l10n = AppLocalizations.of(context)!;

                return AlertDialog(
                  insetPadding: _dialogInsetPadding(context),
                  title: Text(l10n.language),
                  content: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      SegmentedButton<String>(
                        segments: [
                          ButtonSegment(
                            value: kLanguageSystem,
                            label: Text(l10n.languageFollowSystem),
                            icon: const Icon(Icons.computer),
                          ),
                          ButtonSegment(
                            value: kLanguageEnglish,
                            label: Text(l10n.languageEnglish),
                            icon: const Icon(Icons.language),
                          ),
                          ButtonSegment(
                            value: kLanguageChinese,
                            label: Text(l10n.languageChinese),
                            icon: const Icon(Icons.translate),
                          ),
                        ],
                        selected: {currentCode},
                        onSelectionChanged: (Set<String> selection) async {
                          final value = selection.first;
                          await ref
                              .read(localeProvider.notifier)
                              .setLanguageCode(value);
                          if (context.mounted) {
                            Navigator.of(context).pop();
                          }
                        },
                      ),
                      const SizedBox(height: 16),
                      Text(
                        l10n.languageFollowSystem,
                        style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                  actions: [
                    TextButton(
                      onPressed: () => Navigator.of(context).pop(),
                      child: Text(l10n.close),
                    ),
                  ],
                );
              },
            ),
          );
        },
      ),
    );
  }

  /// 显示主题模式对话框
  void _showThemeModeDialog(BuildContext pageContext) {
    showDialog(
      context: pageContext,
      builder: (dialogContext) => LayoutBuilder(
        builder: (dialogContext, constraints) {
          return ConstrainedBox(
            constraints: BoxConstraints(
              maxWidth: _dialogMaxWidth(dialogContext),
            ),
            child: Consumer(
              builder: (dialogContext, ref, _) {
                final themeNotifier = ref.watch(themeModeProvider.notifier);
                final currentCode = themeNotifier.themeModeCode;
                final l10n = AppLocalizations.of(dialogContext)!;

                return AlertDialog(
                  insetPadding: _dialogInsetPadding(dialogContext),
                  title: Text(l10n.theme_mode_select_title),
                  content: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      SegmentedButton<String>(
                        segments: [
                          ButtonSegment(
                            value: kThemeModeSystem,
                            label: Text(l10n.theme_mode_follow_system),
                            icon: const Icon(Icons.brightness_auto),
                          ),
                          ButtonSegment(
                            value: kThemeModeLight,
                            label: Text(l10n.theme_mode_light),
                            icon: const Icon(Icons.light_mode),
                          ),
                          ButtonSegment(
                            value: kThemeModeDark,
                            label: Text(l10n.theme_mode_dark),
                            icon: const Icon(Icons.dark_mode),
                          ),
                        ],
                        selected: {currentCode},
                        onSelectionChanged: (Set<String> selection) async {
                          final value = selection.first;
                          String modeName;
                          if (value == kThemeModeSystem) {
                            modeName = l10n.theme_mode_follow_system;
                          } else if (value == kThemeModeLight) {
                            modeName = l10n.theme_mode_light;
                          } else {
                            modeName = l10n.theme_mode_dark;
                          }
                          await ref
                              .read(themeModeProvider.notifier)
                              .setThemeModeCode(value);
                          if (!dialogContext.mounted) {
                            return;
                          }
                          final noticeMessage = l10n.theme_mode_changed(
                            modeName,
                          );
                          Navigator.of(dialogContext).pop();
                          WidgetsBinding.instance.addPostFrameCallback((_) {
                            Future<void>.delayed(kThemeAnimationDuration, () {
                              if (!pageContext.mounted) {
                                return;
                              }
                              showTopFloatingNotice(
                                pageContext,
                                message: noticeMessage,
                              );
                            });
                          });
                        },
                      ),
                      const SizedBox(height: 16),
                      Text(
                        l10n.theme_mode_subtitle,
                        style: Theme.of(dialogContext).textTheme.bodySmall
                            ?.copyWith(
                              color: Theme.of(
                                dialogContext,
                              ).colorScheme.onSurfaceVariant,
                            ),
                      ),
                    ],
                  ),
                  actions: [
                    TextButton(
                      onPressed: () => Navigator.of(dialogContext).pop(),
                      child: Text(l10n.close),
                    ),
                  ],
                );
              },
            ),
          );
        },
      ),
    );
  }

  /// 显示帮助对话框
  void _showHelpDialog(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    showDialog(
      context: context,
      builder: (context) => LayoutBuilder(
        builder: (context, constraints) {
          return ConstrainedBox(
            constraints: BoxConstraints(maxWidth: _dialogMaxWidth(context)),
            child: AlertDialog(
              insetPadding: _dialogInsetPadding(context),
              title: Text(l10n.profile_help_center),
              content: SizedBox(
                width: double.maxFinite,
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    ListTile(
                      leading: const Icon(Icons.book),
                      title: Text(l10n.profile_user_guide),
                      subtitle: Text(l10n.profile_user_guide_subtitle),
                    ),
                    ListTile(
                      leading: const Icon(Icons.video_library),
                      title: Text(l10n.profile_video_tutorials),
                      subtitle: Text(l10n.profile_video_tutorials_subtitle),
                    ),
                    ListTile(
                      leading: const Icon(Icons.contact_support),
                      title: Text(l10n.profile_contact_support),
                      subtitle: Text(l10n.profile_contact_support_subtitle),
                    ),
                  ],
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: Text(l10n.close),
                ),
              ],
            ),
          );
        },
      ),
    );
  }

  /// 显示关于对话框
  Future<void> _showAboutDialog(BuildContext context) async {
    final l10n = AppLocalizations.of(context)!;
    final packageInfo = await PackageInfo.fromPlatform();
    if (!context.mounted) return;

    showDialog(
      context: context,
      builder: (dialogContext) => LayoutBuilder(
        builder: (context, constraints) {
          return ConstrainedBox(
            constraints: BoxConstraints(maxWidth: _dialogMaxWidth(context)),
            child: AlertDialog(
              insetPadding: _dialogInsetPadding(context),
              title: Row(
                children: [
                  const Icon(Icons.psychology, size: 48),
                  const SizedBox(width: 12),
                  Expanded(child: Text(l10n.appTitle)),
                ],
              ),
              content: SizedBox(
                width: double.maxFinite,
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(l10n.version_label(packageInfo.version)),
                    const SizedBox(height: 4),
                    Text(l10n.build_label(packageInfo.buildNumber)),
                    const SizedBox(height: 8),
                    Text(l10n.profile_about_subtitle),
                  ],
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(dialogContext).pop(),
                  child: Text(l10n.ok),
                ),
              ],
            ),
          );
        },
      ),
    );
  }

  /// Get version subtitle for display
  String _getVersionSubtitle() {
    return _appVersion;
  }

  void _handleVersionTap(BuildContext context) {
    final now = DateTime.now();
    final isWithinWindow =
        _lastVersionTapAt != null &&
        now.difference(_lastVersionTapAt!) <= _versionTapWindow;

    if (!isWithinWindow) {
      _versionTapCount = 0;
    }

    _lastVersionTapAt = now;
    _versionTapCount += 1;
    _versionTapTimer?.cancel();

    if (_versionTapCount >= 5) {
      _resetVersionTapState();
      _showServerConfigDialog(context);
      return;
    }

    _versionTapTimer = Timer(_versionTapWindow, () {
      if (!mounted) return;
      final shouldShowAbout = _versionTapCount == 1;
      _resetVersionTapState();
      if (shouldShowAbout) {
        _showAboutDialog(context);
      }
    });
  }

  void _resetVersionTapState() {
    _versionTapTimer?.cancel();
    _versionTapTimer = null;
    _versionTapCount = 0;
    _lastVersionTapAt = null;
  }

  void _showServerConfigDialog(BuildContext context) {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => const ServerConfigDialog(),
    );
  }

  /// 显示更新检查对话框
  void _showUpdateCheckDialog(BuildContext context) {
    ManualUpdateCheckDialog.show(context);
  }

  /// 显示登出对话框
  void _showLogoutDialog(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    showDialog(
      context: context,
      builder: (dialogContext) => LayoutBuilder(
        builder: (context, constraints) {
          return ConstrainedBox(
            constraints: BoxConstraints(maxWidth: _dialogMaxWidth(context)),
            child: AlertDialog(
              insetPadding: _dialogInsetPadding(context),
              title: Text(l10n.profile_logout_title),
              content: Text(l10n.profile_logout_message),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(dialogContext).pop(),
                  child: Text(l10n.cancel),
                ),
                FilledButton(
                  onPressed: () async {
                    // Close dialog first
                    Navigator.of(dialogContext).pop();

                    // Perform logout
                    await ref.read(authProvider.notifier).logout();

                    // Show success message
                    if (context.mounted) {
                      showTopFloatingNotice(
                        context,
                        message: l10n.profile_logged_out,
                      );
                    }

                    // Navigation will be handled by GoRouter redirect
                  },
                  child: Text(l10n.logout),
                ),
              ],
            ),
          );
        },
      ),
    );
  }
}
