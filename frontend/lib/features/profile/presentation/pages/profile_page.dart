import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/localization/locale_provider.dart';
import 'package:personal_ai_assistant/core/theme/theme_provider.dart';
import 'package:personal_ai_assistant/features/settings/presentation/widgets/update_dialog.dart';

import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../../../auth/presentation/providers/auth_provider.dart';
import '../../../../core/utils/app_logger.dart' as logger;

/// Material Design 3自适应Profile页面
class ProfilePage extends ConsumerStatefulWidget {
  const ProfilePage({super.key});

  @override
  ConsumerState<ProfilePage> createState() => _ProfilePageState();
}

class _ProfilePageState extends ConsumerState<ProfilePage> {
  bool _notificationsEnabled = true;
  bool _autoSyncEnabled = true;
  String _appVersion = 'Loading...';

  @override
  void initState() {
    super.initState();
    _loadVersion();
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

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;

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
                        style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                              fontWeight: FontWeight.bold,
                            ),
                      ),
                    ),
                    const SizedBox(width: 16),
                    // 设置按钮
                    IconButton(
                      onPressed: () {
                        context.push('/profile/settings');
                      },
                      icon: const Icon(Icons.settings),
                      tooltip: l10n.settings,
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 8),

              // 用户信息卡片
              _buildUserProfileCard(context),

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

  /// 构建用户信息卡片
  Widget _buildUserProfileCard(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final screenWidth = MediaQuery.of(context).size.width;
    final isMobile = screenWidth < 600;
    final authState = ref.watch(authProvider);
    final user = authState.user;

    return Card(
      margin: EdgeInsets.zero,
      child: Padding(
        padding: EdgeInsets.all(isMobile ? 16 : 24),
        child: Row(
          children: [
            // 头像
            Container(
              width: isMobile ? 80 : 100,
              height: isMobile ? 80 : 100,
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.primaryContainer,
                shape: BoxShape.circle,
                image: user?.avatarUrl != null
                    ? DecorationImage(
                        image: NetworkImage(user!.avatarUrl!),
                        fit: BoxFit.cover,
                      )
                    : null,
              ),
              child: user?.avatarUrl == null
                  ? Icon(
                      Icons.person,
                      size: isMobile ? 40 : 50,
                      color: Theme.of(context).colorScheme.onPrimaryContainer,
                    )
                  : null,
            ),
            const SizedBox(width: 24),
            // 用户信息
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // 用户名 + Verified 图标
                  Row(
                    children: [
                      Flexible(
                        child: Text(
                          user?.displayName ?? l10n.profile_guest_user,
                          style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                                fontWeight: FontWeight.bold,
                              ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Tooltip(
                        message: l10n.profile_verified,
                        child: Icon(
                          Icons.verified,
                          size: 20,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Text(
                    user?.email ?? l10n.profile_please_login,
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                  ),
                  const SizedBox(height: 8),
                  // Premium Chip
                  Chip(
                    visualDensity: VisualDensity.compact,
                    padding: EdgeInsets.zero,
                    labelPadding: const EdgeInsets.only(left: 2, right: 8),
                    avatar: Icon(
                      Icons.workspace_premium,
                      size: 14,
                      color: Theme.of(context).colorScheme.onPrimaryContainer,
                    ),
                    label: Text(l10n.profile_premium),
                    backgroundColor: Theme.of(context).colorScheme.primaryContainer,
                    labelStyle: Theme.of(context).textTheme.labelSmall?.copyWith(
                      color: Theme.of(context).colorScheme.onPrimaryContainer,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 16),
            // 登出按钮
            IconButton(
              onPressed: () {
                _showLogoutDialog(context);
              },
              icon: const Icon(Icons.logout),
              tooltip: l10n.logout,
              style: IconButton.styleFrom(
                foregroundColor: Theme.of(context).colorScheme.error,
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// 构建活动统计卡片
  Widget _buildActivityCards(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final screenWidth = MediaQuery.of(context).size.width;
    final isMobile = screenWidth < 600;

    // On narrow screens, stack cards vertically to prevent squishing
    if (isMobile) {
      return Column(
        children: [
          _buildActivityCard(
            context,
            Icons.podcasts,
            l10n.nav_podcast,
            '42',
            Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(height: 12),
          _buildActivityCard(
            context,
            Icons.chat,
            l10n.nav_assistant,
            '1,024',
            Theme.of(context).colorScheme.tertiary,
          ),
        ],
      );
    }

    // Desktop: horizontal layout
    return Row(
      children: [
        Expanded(
          child: _buildActivityCard(
            context,
            Icons.podcasts,
            l10n.nav_podcast,
            '42',
            Theme.of(context).colorScheme.primary,
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: _buildActivityCard(
            context,
            Icons.chat,
            l10n.nav_assistant,
            '1,024',
            Theme.of(context).colorScheme.tertiary,
          ),
        ),
      ],
    );
  }

  Widget _buildActivityCard(BuildContext context, IconData icon, String label, String value, Color color) {
    return Card(
      margin: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            Icon(icon, color: color, size: 24),
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
                    style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
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
              icon: Icons.person,
              title: l10n.profile_edit_profile,
              subtitle: l10n.profile_edit_profile_subtitle,
              onTap: () => _showEditProfileDialog(context),
            ),
            _buildSettingsItem(
              context,
              icon: Icons.security,
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
            _buildSettingsItem(
              context,
              icon: Icons.sync,
              title: l10n.profile_auto_sync,
              subtitle: l10n.profile_auto_sync_subtitle,
              trailing: Switch(
                value: _autoSyncEnabled,
                onChanged: (value) {
                  setState(() {
                    _autoSyncEnabled = value;
                  });
                },
              ),
            ),
          ]),
          const SizedBox(height: 24),
          _buildSettingsSection(context, 'Support', [
            _buildSettingsItem(
              context,
              icon: Icons.help,
              title: l10n.profile_help_center,
              subtitle: l10n.profile_help_center_subtitle,
              onTap: () => _showHelpDialog(context),
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
              onTap: () => _showAboutDialog(context),
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
                _buildSettingsSection(context, l10n.profile_account_settings, [
                  _buildSettingsItem(
                    context,
                    icon: Icons.person,
                    title: l10n.profile_edit_profile,
                    subtitle: l10n.profile_edit_profile_subtitle,
                    onTap: () => _showEditProfileDialog(context),
                  ),
                  _buildSettingsItem(
                    context,
                    icon: Icons.security,
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
                  _buildSettingsItem(
                    context,
                    icon: Icons.sync,
                    title: l10n.profile_auto_sync,
                    subtitle: l10n.profile_auto_sync_subtitle,
                    trailing: Switch(
                      value: _autoSyncEnabled,
                      onChanged: (value) {
                        setState(() {
                          _autoSyncEnabled = value;
                        });
                      },
                    ),
                  ),
                ]),
              ],
            ),
          ),
          ],
        ),
        const SizedBox(height: 24),
        _buildSettingsSection(context, 'Support', [
          _buildSettingsItem(
            context,
            icon: Icons.help,
            title: l10n.profile_help_center,
            subtitle: l10n.profile_help_center_subtitle,
            onTap: () => _showHelpDialog(context),
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
            onTap: () => _showAboutDialog(context),
          ),
        ]),
      ],
      );
    }
  }

  /// 统一的 Card 样式封装，确保所有卡片 margin 一致
  // 保留此方法以便将来统一使用，目前所有卡片已手动设置 margin: EdgeInsets.zero
  // ignore: unused_element
  Widget _buildCard(Widget child) => Card(
        margin: EdgeInsets.zero,
        child: child,
      );

  /// 构建设置分组
  Widget _buildSettingsSection(BuildContext context, String title, List<Widget> children) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.only(top: 8, bottom: 8),
          child: Text(
            title,
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
                  fontWeight: FontWeight.bold,
                  color: Theme.of(context).colorScheme.primary,
                ),
          ),
        ),
        Card(
          margin: EdgeInsets.zero,
          child: Column(children: children),
        ),
      ],
    );
  }

  /// 构建设置项目
  Widget _buildSettingsItem(
    BuildContext context, {
    required IconData icon,
    required String title,
    required String subtitle,
    Widget? trailing,
    VoidCallback? onTap,
  }) {
    return ListTile(
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
          // 计算对话框最大宽度，与卡片列宽度保持一致
          final screenWidth = MediaQuery.of(context).size.width;
          final dialogMaxWidth = screenWidth < 600 ? screenWidth - 32 : 560.0;

          return ConstrainedBox(
            constraints: BoxConstraints(maxWidth: dialogMaxWidth),
            child: AlertDialog(
              insetPadding: const EdgeInsets.all(16),
              title: Text(l10n.profile_edit_profile),
              content: Column(
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
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: Text(l10n.cancel),
                ),
                FilledButton(
                  onPressed: () {
                    Navigator.of(context).pop();
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text(l10n.profile_updated_successfully)),
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
          final screenWidth = MediaQuery.of(context).size.width;
          final dialogMaxWidth = screenWidth < 600 ? screenWidth - 32 : 560.0;

          return ConstrainedBox(
            constraints: BoxConstraints(maxWidth: dialogMaxWidth),
            child: AlertDialog(
              insetPadding: const EdgeInsets.all(16),
              title: Text(l10n.profile_security),
              content: Column(
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
          final screenWidth = MediaQuery.of(context).size.width;
          final dialogMaxWidth = screenWidth < 600 ? screenWidth - 32 : 560.0;

          return ConstrainedBox(
            constraints: BoxConstraints(maxWidth: dialogMaxWidth),
            child: Consumer(
              builder: (context, ref, _) {
                final localeNotifier = ref.watch(localeProvider.notifier);
                final currentCode = localeNotifier.languageCode;
                final l10n = AppLocalizations.of(context)!;

                return AlertDialog(
                  insetPadding: const EdgeInsets.all(16),
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
                          await ref.read(localeProvider.notifier).setLanguageCode(value);
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
  void _showThemeModeDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => LayoutBuilder(
        builder: (context, constraints) {
          final screenWidth = MediaQuery.of(context).size.width;
          final dialogMaxWidth = screenWidth < 600 ? screenWidth - 32 : 560.0;

          return ConstrainedBox(
            constraints: BoxConstraints(maxWidth: dialogMaxWidth),
            child: Consumer(
              builder: (context, ref, _) {
                final themeNotifier = ref.watch(themeModeProvider.notifier);
                final currentCode = themeNotifier.themeModeCode;
                final l10n = AppLocalizations.of(context)!;

                return AlertDialog(
                  insetPadding: const EdgeInsets.all(16),
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
                          await ref.read(themeModeProvider.notifier).setThemeModeCode(value);
                          if (context.mounted) {
                            Navigator.of(context).pop();
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(content: Text(l10n.theme_mode_changed(modeName))),
                            );
                          }
                        },
                      ),
                      const SizedBox(height: 16),
                      Text(
                        l10n.theme_mode_subtitle,
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

  /// 显示帮助对话框
  void _showHelpDialog(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    showDialog(
      context: context,
      builder: (context) => LayoutBuilder(
        builder: (context, constraints) {
          final screenWidth = MediaQuery.of(context).size.width;
          final dialogMaxWidth = screenWidth < 600 ? screenWidth - 32 : 560.0;

          return ConstrainedBox(
            constraints: BoxConstraints(maxWidth: dialogMaxWidth),
            child: AlertDialog(
              insetPadding: const EdgeInsets.all(16),
              title: Text(l10n.profile_help_center),
              content: Column(
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

    showAboutDialog(
      context: context,
      applicationName: l10n.appTitle,
      applicationVersion: packageInfo.version,
      applicationIcon: const Icon(Icons.psychology, size: 48),
      children: [
        Text(l10n.profile_about_subtitle),
        const SizedBox(height: 8),
        Text('Build: ${packageInfo.buildNumber}'),
      ],
    );
  }

  /// Get version subtitle for display
  String _getVersionSubtitle() {
    return _appVersion;
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
          final screenWidth = MediaQuery.of(context).size.width;
          final dialogMaxWidth = screenWidth < 600 ? screenWidth - 32 : 560.0;

          return ConstrainedBox(
            constraints: BoxConstraints(maxWidth: dialogMaxWidth),
            child: AlertDialog(
              insetPadding: const EdgeInsets.all(16),
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
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text(l10n.profile_logged_out)),
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