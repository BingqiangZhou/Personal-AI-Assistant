import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/localization/locale_provider.dart';
import 'package:personal_ai_assistant/features/settings/presentation/widgets/update_dialog.dart';

import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../../../auth/presentation/providers/auth_provider.dart';

/// Material Design 3自适应Profile页面
class ProfilePage extends ConsumerStatefulWidget {
  const ProfilePage({super.key});

  @override
  ConsumerState<ProfilePage> createState() => _ProfilePageState();
}

class _ProfilePageState extends ConsumerState<ProfilePage> {
  bool _notificationsEnabled = true;
  bool _darkModeEnabled = false;
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
      debugPrint('Error loading version: $e');
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
                Row(
                  children: [
                    // 设置按钮
                    FilledButton(
                      onPressed: () {
                        context.push('/profile/settings');
                      },
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const Icon(Icons.settings, size: 16),
                          const SizedBox(width: 4),
                          Text(l10n.settings),
                        ],
                      ),
                    ),
                    const SizedBox(width: 12),
                    // 登出按钮
                    FilledButton.icon(
                      onPressed: () {
                        _showLogoutDialog(context);
                      },
                      style: FilledButton.styleFrom(
                        backgroundColor: Theme.of(context).colorScheme.errorContainer,
                        foregroundColor: Theme.of(context).colorScheme.onErrorContainer,
                      ),
                      icon: const Icon(Icons.logout),
                      label: Text(l10n.logout),
                    ),
                  ],
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),

          // 用户信息卡片
          _buildUserProfileCard(context),

          const SizedBox(height: 24),

          // 统计和活动卡片
          _buildActivityCards(context),

          const SizedBox(height: 24),

          // 设置选项
          _buildSettingsContent(context),

          // 底部空间
          const SizedBox(height: 32),
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
                  Text(
                    user?.displayName ?? l10n.profile_guest_user,
                    style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    user?.email ?? l10n.profile_please_login,
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                  ),
                  const SizedBox(height: 8),
                  Row(
                    children: [
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
                      const SizedBox(width: 4),
                      Chip(
                        visualDensity: VisualDensity.compact,
                        padding: EdgeInsets.zero,
                        labelPadding: const EdgeInsets.only(left: 2, right: 8),
                        avatar: Icon(
                          Icons.verified,
                          size: 14,
                          color: Theme.of(context).colorScheme.onSecondaryContainer,
                        ),
                        label: Text(l10n.profile_verified),
                        backgroundColor: Theme.of(context).colorScheme.secondaryContainer,
                        labelStyle: Theme.of(context).textTheme.labelSmall?.copyWith(
                          color: Theme.of(context).colorScheme.onSecondaryContainer,
                        ),
                      ),
                    ],
                  ),
                ],
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
            Icons.article,
            l10n.nav_knowledge,
            '128',
            Theme.of(context).colorScheme.secondary,
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
            Icons.article,
            l10n.nav_knowledge,
            '128',
            Theme.of(context).colorScheme.secondary,
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
            _buildSettingsItem(
              context,
              icon: Icons.dark_mode,
              title: l10n.profile_dark_mode,
              subtitle: l10n.profile_dark_mode_subtitle,
              trailing: Switch(
                value: _darkModeEnabled,
                onChanged: (value) {
                  setState(() {
                    _darkModeEnabled = value;
                  });
                },
              ),
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
                  _buildSettingsItem(
                    context,
                    icon: Icons.dark_mode,
                    title: l10n.profile_dark_mode,
                    subtitle: l10n.profile_dark_mode_subtitle,
                    trailing: Switch(
                      value: _darkModeEnabled,
                      onChanged: (value) {
                        setState(() {
                          _darkModeEnabled = value;
                        });
                      },
                    ),
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

  /// 构建设置分组
  Widget _buildSettingsSection(BuildContext context, String title, List<Widget> children) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.only(left: 16, top: 8, bottom: 8),
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
      builder: (context) => AlertDialog(
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
  }

  /// 显示安全对话框
  void _showSecurityDialog(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
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
  }

  /// 显示语言对话框
  void _showLanguageDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => Consumer(
        builder: (context, ref, _) {
          final localeNotifier = ref.watch(localeProvider.notifier);
          final currentCode = localeNotifier.languageCode;
          final l10n = AppLocalizations.of(context)!;

          return AlertDialog(
            title: Text(l10n.language),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                RadioListTile<String>(
                  title: Text(l10n.languageFollowSystem),
                  value: kLanguageSystem,
                  groupValue: currentCode,
                  onChanged: (value) async {
                    if (value != null) {
                      await ref.read(localeProvider.notifier).setLanguageCode(value);
                      if (context.mounted) {
                        Navigator.of(context).pop();
                      }
                    }
                  },
                ),
                RadioListTile<String>(
                  title: Text(l10n.languageEnglish),
                  value: kLanguageEnglish,
                  groupValue: currentCode,
                  onChanged: (value) async {
                    if (value != null) {
                      await ref.read(localeProvider.notifier).setLanguageCode(value);
                      if (context.mounted) {
                        Navigator.of(context).pop();
                      }
                    }
                  },
                ),
                RadioListTile<String>(
                  title: Text(l10n.languageChinese),
                  value: kLanguageChinese,
                  groupValue: currentCode,
                  onChanged: (value) async {
                    if (value != null) {
                      await ref.read(localeProvider.notifier).setLanguageCode(value);
                      if (context.mounted) {
                        Navigator.of(context).pop();
                      }
                    }
                  },
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
  }

  /// 显示帮助对话框
  void _showHelpDialog(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
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
      builder: (dialogContext) => AlertDialog(
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
  }
}