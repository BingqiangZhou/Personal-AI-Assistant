import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../../../auth/domain/models/user.dart';
import '../../../user/presentation/providers/user_provider.dart';

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
  String _language = 'English';

  @override
  Widget build(BuildContext context) {
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
                    'Profile',
                    style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                  ),
                ),
                const SizedBox(width: 16),
                Row(
                  children: [
                    // 设置按钮
                    FilledButton.tonal(
                      onPressed: () {
                        context.push('/profile/settings');
                      },
                      child: const Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(Icons.settings, size: 16),
                          SizedBox(width: 4),
                          Text('Settings'),
                        ],
                      ),
                    ),
                    const SizedBox(width: 12),
                    // 编辑按钮
                    FilledButton.icon(
                      onPressed: () {
                        _showEditProfileDialog(context);
                      },
                      icon: const Icon(Icons.edit),
                      label: const Text('Edit'),
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
        ],
      ),
      ),
    );
  }

  /// 构建用户信息卡片
  Widget _buildUserProfileCard(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;
    final isMobile = screenWidth < 600;
    final userState = ref.watch(userProvider);

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
                image: userState.value?.avatarUrl != null
                    ? DecorationImage(
                        image: NetworkImage(userState.value!.avatarUrl!),
                        fit: BoxFit.cover,
                      )
                    : null,
              ),
              child: userState.value?.avatarUrl == null
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
                  userState.when(
                    data: (user) => Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          user?.displayName ?? 'Guest User',
                          style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                                fontWeight: FontWeight.bold,
                              ),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          user?.email ?? 'Please log in',
                          style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                                color: Theme.of(context).colorScheme.onSurfaceVariant,
                              ),
                        ),
                      ],
                    ),
                    loading: () => const CircularProgressIndicator(),
                    error: (e, s) => Text('Error loading profile'),
                  ),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Chip(
                        avatar: Icon(
                          Icons.workspace_premium,
                          size: 16,
                          color: Theme.of(context).colorScheme.onPrimaryContainer,
                        ),
                        label: const Text('Premium'),
                        backgroundColor: Theme.of(context).colorScheme.primaryContainer,
                        labelStyle: TextStyle(
                          color: Theme.of(context).colorScheme.onPrimaryContainer,
                        ),
                      ),
                      const SizedBox(width: 8),
                      Chip(
                        avatar: Icon(
                          Icons.verified,
                          size: 16,
                          color: Theme.of(context).colorScheme.onSecondaryContainer,
                        ),
                        label: const Text('Verified'),
                        backgroundColor: Theme.of(context).colorScheme.secondaryContainer,
                        labelStyle: TextStyle(
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
    final screenWidth = MediaQuery.of(context).size.width;
    final isMobile = screenWidth < 600;

    // On narrow screens, stack cards vertically to prevent squishing
    if (isMobile) {
      return Column(
        children: [
          _buildActivityCard(
            context,
            Icons.podcasts,
            'Podcasts',
            '42',
            Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(height: 12),
          _buildActivityCard(
            context,
            Icons.article,
            'Knowledge',
            '128',
            Theme.of(context).colorScheme.secondary,
          ),
          const SizedBox(height: 12),
          _buildActivityCard(
            context,
            Icons.chat,
            'AI Chats',
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
            'Podcasts',
            '42',
            Theme.of(context).colorScheme.primary,
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: _buildActivityCard(
            context,
            Icons.article,
            'Knowledge',
            '128',
            Theme.of(context).colorScheme.secondary,
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: _buildActivityCard(
            context,
            Icons.chat,
            'AI Chats',
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
    final screenWidth = MediaQuery.of(context).size.width;
    final isMobile = screenWidth < 600;

    if (isMobile) {
      return Column(
        children: [
          _buildSettingsSection(context, 'Account Settings', [
            _buildSettingsItem(
              context,
              icon: Icons.person,
              title: 'Edit Profile',
              subtitle: 'Update your personal information',
              onTap: () => _showEditProfileDialog(context),
            ),
            _buildSettingsItem(
              context,
              icon: Icons.security,
              title: 'Security',
              subtitle: 'Password, authentication, and privacy',
              onTap: () => _showSecurityDialog(context),
            ),
            _buildSettingsItem(
              context,
              icon: Icons.notifications,
              title: 'Notifications',
              subtitle: 'Push notifications and email alerts',
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
          _buildSettingsSection(context, 'Preferences', [
            _buildSettingsItem(
              context,
              icon: Icons.language,
              title: 'Language',
              subtitle: _language,
              onTap: () => _showLanguageDialog(context),
            ),
            _buildSettingsItem(
              context,
              icon: Icons.dark_mode,
              title: 'Dark Mode',
              subtitle: 'Toggle dark theme',
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
              title: 'Auto Sync',
              subtitle: 'Automatically sync data across devices',
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
              title: 'Help Center',
              subtitle: 'Get help and support',
              onTap: () => _showHelpDialog(context),
            ),
            _buildSettingsItem(
              context,
              icon: Icons.info,
              title: 'About',
              subtitle: 'App version and information',
              onTap: () => _showAboutDialog(context),
            ),
          ]),
          const SizedBox(height: 24),
          // 登出按钮
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: FilledButton.tonal(
              onPressed: () => _showLogoutDialog(context),
              style: FilledButton.styleFrom(
                backgroundColor: Theme.of(context).colorScheme.errorContainer,
                foregroundColor: Theme.of(context).colorScheme.onErrorContainer,
              ),
              child: const Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(Icons.logout),
                  SizedBox(width: 8),
                  Text('Logout'),
                ],
              ),
            ),
          ),
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
                _buildSettingsSection(context, 'Account Settings', [
                  _buildSettingsItem(
                    context,
                    icon: Icons.person,
                    title: 'Edit Profile',
                    subtitle: 'Update your personal information',
                    onTap: () => _showEditProfileDialog(context),
                  ),
                  _buildSettingsItem(
                    context,
                    icon: Icons.security,
                    title: 'Security',
                    subtitle: 'Password, authentication, and privacy',
                    onTap: () => _showSecurityDialog(context),
                  ),
                  _buildSettingsItem(
                    context,
                    icon: Icons.notifications,
                    title: 'Notifications',
                    subtitle: 'Push notifications and email alerts',
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
                _buildSettingsSection(context, 'Preferences', [
                  _buildSettingsItem(
                    context,
                    icon: Icons.language,
                    title: 'Language',
                    subtitle: _language,
                    onTap: () => _showLanguageDialog(context),
                  ),
                  _buildSettingsItem(
                    context,
                    icon: Icons.dark_mode,
                    title: 'Dark Mode',
                    subtitle: 'Toggle dark theme',
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
                    title: 'Auto Sync',
                    subtitle: 'Automatically sync data across devices',
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
            title: 'Help Center',
            subtitle: 'Get help and support',
            onTap: () => _showHelpDialog(context),
          ),
          _buildSettingsItem(
            context,
            icon: Icons.info,
            title: 'About',
            subtitle: 'App version and information',
            onTap: () => _showAboutDialog(context),
          ),
        ]),
        const SizedBox(height: 24),
        // 登出按钮
        SizedBox(
          width: double.infinity,
          child: FilledButton.tonal(
            onPressed: () => _showLogoutDialog(context),
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(context).colorScheme.errorContainer,
              foregroundColor: Theme.of(context).colorScheme.onErrorContainer,
              minimumSize: const Size(double.infinity, 48),
            ),
            child: const Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(Icons.logout),
                SizedBox(width: 8),
                Text('Logout'),
              ],
            ),
          ),
        ),
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
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Edit Profile'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const TextField(
              decoration: InputDecoration(
                labelText: 'Name',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 16),
            const TextField(
              decoration: InputDecoration(
                labelText: 'Email',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 16),
            const TextField(
              decoration: InputDecoration(
                labelText: 'Bio',
                border: OutlineInputBorder(),
              ),
              maxLines: 3,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () {
              Navigator.of(context).pop();
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Profile updated successfully')),
              );
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
  }

  /// 显示设置对话框
  void _showSettingsDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Settings'),
        content: const Text('Advanced settings coming soon!'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  /// 显示安全对话框
  void _showSecurityDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Security'),
        content: const Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: Icon(Icons.password),
              title: Text('Change Password'),
              trailing: Icon(Icons.chevron_right),
            ),
            ListTile(
              leading: Icon(Icons.fingerprint),
              title: Text('Biometric Authentication'),
              trailing: Switch(value: true, onChanged: null),
            ),
            ListTile(
              leading: Icon(Icons.phone_android),
              title: Text('Two-Factor Authentication'),
              trailing: Icon(Icons.chevron_right),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  /// 显示语言对话框
  void _showLanguageDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Select Language'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            RadioListTile<String>(
              title: const Text('English'),
              value: 'English',
              groupValue: _language,
              onChanged: (value) {
                setState(() {
                  _language = value!;
                });
                Navigator.of(context).pop();
              },
            ),
            RadioListTile<String>(
              title: const Text('中文'),
              value: '中文',
              groupValue: _language,
              onChanged: (value) {
                setState(() {
                  _language = value!;
                });
                Navigator.of(context).pop();
              },
            ),
            RadioListTile<String>(
              title: const Text('Español'),
              value: 'Español',
              groupValue: _language,
              onChanged: (value) {
                setState(() {
                  _language = value!;
                });
                Navigator.of(context).pop();
              },
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
        ],
      ),
    );
  }

  /// 显示帮助对话框
  void _showHelpDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Help Center'),
        content: const Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: Icon(Icons.book),
              title: Text('User Guide'),
              subtitle: Text('Learn how to use the app'),
            ),
            ListTile(
              leading: Icon(Icons.video_library),
              title: Text('Video Tutorials'),
              subtitle: Text('Watch step-by-step guides'),
            ),
            ListTile(
              leading: Icon(Icons.contact_support),
              title: Text('Contact Support'),
              subtitle: Text('Get help from our team'),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  /// 显示关于对话框
  void _showAboutDialog(BuildContext context) {
    showAboutDialog(
      context: context,
      applicationName: 'Personal AI Assistant',
      applicationVersion: '1.0.0',
      applicationIcon: const Icon(Icons.psychology, size: 48),
      children: const [
        Text('A comprehensive personal AI assistant for knowledge management and productivity.'),
      ],
    );
  }

  /// 显示登出对话框
  void _showLogoutDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Logout'),
        content: const Text('Are you sure you want to logout?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () {
              Navigator.of(context).pop();
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Logged out successfully')),
              );
            },
            child: const Text('Logout'),
          ),
        ],
      ),
    );
  }
}