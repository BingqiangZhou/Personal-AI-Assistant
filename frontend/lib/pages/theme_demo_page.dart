import 'package:flutter/material.dart';

import '../core/theme/app_colors.dart';

/// Theme Demo Page / 主题演示页面
///
/// Showcases all common UI components in both Light and Dark themes
/// 展示所有常用 UI 组件在亮色和暗色主题下的效果
class ThemeDemoPage extends StatefulWidget {
  const ThemeDemoPage({super.key});

  @override
  State<ThemeDemoPage> createState() => _ThemeDemoPageState();
}

class _ThemeDemoPageState extends State<ThemeDemoPage> {
  final TextEditingController _textController = TextEditingController();
  final List<String> _selectedChips = <String>[];
  final List<String> _chipOptions = const [
    'React',
    'Flutter',
    'Python',
    'FastAPI',
    'Docker',
    'Kubernetes',
  ];

  int _bottomNavIndex = 0;

  @override
  void dispose() {
    _textController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final isDark = theme.brightness == Brightness.dark;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Mindriver Theme Demo / 主题演示'),
        actions: [
          // Theme toggle button
          IconButton(
            icon: Icon(isDark ? Icons.light_mode : Icons.dark_mode),
            onPressed: () {
              // In a real app, you'd use a theme provider
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text(isDark ? 'Switch to Light Mode' : '切换到暗色模式'),
                  duration: const Duration(seconds: 1),
                ),
              );
            },
            tooltip: 'Toggle Theme / 切换主题',
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Brand gradient showcase
            _buildSectionHeader('Brand Gradient / 品牌渐变'),
            const SizedBox(height: 12),
            Container(
              height: 80,
              width: double.infinity,
              decoration: BoxDecoration(
                gradient: isDark
                    ? AppColors.darkBrandGradient
                    : AppColors.mindriverGradient,
                borderRadius: BorderRadius.circular(16),
              ),
              alignment: Alignment.center,
              child: Text(
                'Mindriver AI Assistant',
                style: theme.textTheme.headlineMedium?.copyWith(
                  color: isDark ? AppColors.darkTextPrimary : AppColors.darkBackground,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
            const SizedBox(height: 24),

            // Color palette showcase
            _buildSectionHeader('Color Palette / 色板展示'),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                _buildColorChip('Primary', AppColors.primary),
                _buildColorChip('River', AppColors.riverAccent),
                _buildColorChip('Aqua', AppColors.aqua),
                _buildColorChip('Indigo', AppColors.indigo),
                _buildColorChip('Sun Glow', AppColors.sunGlow),
                _buildColorChip('Sun Ray', AppColors.sunRay),
                _buildColorChip('Leaf', AppColors.leaf),
                _buildColorChip('Mint', AppColors.mint),
              ],
            ),
            const SizedBox(height: 24),

            // Typography showcase
            _buildSectionHeader('Typography / 字体排版'),
            const SizedBox(height: 12),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Display Large', style: theme.textTheme.displayLarge),
                    Text('Display Medium', style: theme.textTheme.displayMedium),
                    Text('Display Small', style: theme.textTheme.displaySmall),
                    const Divider(height: 24),
                    Text('Headline Large', style: theme.textTheme.headlineLarge),
                    Text('Headline Medium', style: theme.textTheme.headlineMedium),
                    Text('Headline Small', style: theme.textTheme.headlineSmall),
                    const Divider(height: 24),
                    Text('Title Large', style: theme.textTheme.titleLarge),
                    Text('Title Medium', style: theme.textTheme.titleMedium),
                    Text('Title Small', style: theme.textTheme.titleSmall),
                    const Divider(height: 24),
                    Text('Body Large', style: theme.textTheme.bodyLarge),
                    Text('Body Medium', style: theme.textTheme.bodyMedium),
                    Text('Body Small', style: theme.textTheme.bodySmall),
                    const Divider(height: 24),
                    Text('Label Large', style: theme.textTheme.labelLarge),
                    Text('Label Medium', style: theme.textTheme.labelMedium),
                    Text('Label Small', style: theme.textTheme.labelSmall),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),

            // Buttons showcase
            _buildSectionHeader('Buttons / 按钮'),
            const SizedBox(height: 12),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    ElevatedButton(
                      onPressed: () {},
                      child: const Text('Elevated Button / 凸起按钮'),
                    ),
                    const SizedBox(height: 12),
                    const ElevatedButton(
                      onPressed: null,
                      child: Text('Disabled ElevatedButton / 禁用状态'),
                    ),
                    const SizedBox(height: 12),
                    TextButton(
                      onPressed: () {},
                      child: const Text('Text Button / 文本按钮'),
                    ),
                    const SizedBox(height: 12),
                    OutlinedButton(
                      onPressed: () {},
                      child: const Text('Outlined Button / 轮廓按钮'),
                    ),
                    const SizedBox(height: 12),
                    OutlinedButton.icon(
                      onPressed: () {},
                      icon: const Icon(Icons.add),
                      label: const Text('Icon Button / 图标按钮'),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),

            // Input fields showcase
            _buildSectionHeader('Input Fields / 输入框'),
            const SizedBox(height: 12),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    TextField(
                      controller: _textController,
                      decoration: const InputDecoration(
                        labelText: 'Username / 用户名',
                        hintText: 'Enter your username / 请输入用户名',
                        prefixIcon: Icon(Icons.person),
                      ),
                    ),
                    const SizedBox(height: 16),
                    const TextField(
                      decoration: InputDecoration(
                        labelText: 'Email / 邮箱',
                        hintText: 'Enter your email / 请输入邮箱',
                        prefixIcon: Icon(Icons.email),
                      ),
                      keyboardType: TextInputType.emailAddress,
                    ),
                    const SizedBox(height: 16),
                    const TextField(
                      decoration: InputDecoration(
                        labelText: 'Password / 密码',
                        hintText: 'Enter your password / 请输入密码',
                        prefixIcon: Icon(Icons.lock),
                        errorText: 'Password is too short / 密码太短',
                      ),
                      obscureText: true,
                    ),
                    const SizedBox(height: 16),
                    const TextField(
                      decoration: InputDecoration(
                        labelText: 'Disabled / 禁用状态',
                        hintText: 'This field is disabled / 此字段已禁用',
                        prefixIcon: Icon(Icons.block),
                      ),
                      enabled: false,
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),

            // Chips showcase
            _buildSectionHeader('Chips / 标签'),
            const SizedBox(height: 12),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Filter Chips / 过滤标签:'),
                    const SizedBox(height: 12),
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: _chipOptions.map((chip) {
                        final isSelected = _selectedChips.contains(chip);
                        return FilterChip(
                          label: Text(chip),
                          selected: isSelected,
                          onSelected: (selected) {
                            setState(() {
                              if (selected) {
                                _selectedChips.add(chip);
                              } else {
                                _selectedChips.remove(chip);
                              }
                            });
                          },
                        );
                      }).toList(),
                    ),
                    const SizedBox(height: 16),
                    const Text('Action Chips / 操作标签:'),
                    const SizedBox(height: 12),
                    const Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        ActionChip(
                          avatar: Icon(Icons.play_arrow),
                          label: Text('Play / 播放'),
                        ),
                        ActionChip(
                          avatar: Icon(Icons.pause),
                          label: Text('Pause / 暂停'),
                        ),
                        ActionChip(
                          avatar: Icon(Icons.stop),
                          label: Text('Stop / 停止'),
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),
                    const Text('Choice Chips / 选择标签:'),
                    const SizedBox(height: 12),
                    const Row(
                      children: [
                        ChoiceChip(
                          label: Text('Option A'),
                          selected: true,
                        ),
                        SizedBox(width: 8),
                        ChoiceChip(
                          label: Text('Option B'),
                          selected: false,
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),

            // ListTile showcase
            _buildSectionHeader('List Tiles / 列表项'),
            const SizedBox(height: 12),
            Card(
              child: Column(
                children: [
                  ListTile(
                    leading: const Icon(Icons.inbox),
                    title: const Text('Inbox / 收件箱'),
                    subtitle: const Text('3 new messages / 3条新消息'),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () {},
                  ),
                  const Divider(height: 1),
                  ListTile(
                    leading: const Icon(Icons.send),
                    title: const Text('Sent / 已发送'),
                    subtitle: const Text('12 messages / 12条消息'),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () {},
                  ),
                  const Divider(height: 1),
                  ListTile(
                    leading: const Icon(Icons.delete),
                    title: const Text('Trash / 垃圾箱'),
                    subtitle: const Text('Empty / 空'),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () {},
                  ),
                  const Divider(height: 1),
                  ListTile(
                    leading: const Icon(Icons.settings),
                    title: const Text('Settings / 设置'),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () {},
                  ),
                ],
              ),
            ),
            const SizedBox(height: 24),

            // SnackBar showcase
            _buildSectionHeader('SnackBar / 提示条'),
            const SizedBox(height: 12),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    ElevatedButton(
                      onPressed: () {
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(
                            content: Text('This is a normal SnackBar / 普通提示条'),
                          ),
                        );
                      },
                      child: const Text('Show SnackBar / 显示提示条'),
                    ),
                    const SizedBox(height: 12),
                    ElevatedButton(
                      onPressed: () {
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(
                            content: const Text('Action SnackBar / 操作提示条'),
                            action: SnackBarAction(
                              label: 'Undo / 撤销',
                              onPressed: () {},
                            ),
                          ),
                        );
                      },
                      child: const Text('Show Action SnackBar / 显示操作提示条'),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),

            // Divider showcase
            _buildSectionHeader('Dividers / 分割线'),
            const SizedBox(height: 12),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Content above / 上方内容'),
                    const Divider(),
                    const Text('Content below / 下方内容'),
                    const SizedBox(height: 16),
                    const Text('With height / 指定高度:'),
                    const Divider(height: 32, thickness: 2),
                    const Text('After thick divider / 粗分割线后'),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),

            // Card variations
            _buildSectionHeader('Card Variations / 卡片变体'),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        children: [
                          Icon(
                            Icons.favorite,
                            color: colorScheme.primary,
                            size: 32,
                          ),
                          const SizedBox(height: 8),
                          Text(
                            'Primary',
                            style: theme.textTheme.titleMedium,
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
                Expanded(
                  child: Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        children: [
                          Icon(
                            Icons.star,
                            color: colorScheme.secondary,
                            size: 32,
                          ),
                          const SizedBox(height: 8),
                          Text(
                            'Secondary',
                            style: theme.textTheme.titleMedium,
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
                Expanded(
                  child: Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        children: [
                          Icon(
                            Icons.eco,
                            color: colorScheme.tertiary,
                            size: 32,
                          ),
                          const SizedBox(height: 8),
                          Text(
                            'Tertiary',
                            style: theme.textTheme.titleMedium,
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 100), // Extra space for bottom nav
          ],
        ),
      ),
      // Bottom navigation bar
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: _bottomNavIndex,
        onTap: (index) {
          setState(() {
            _bottomNavIndex = index;
          });
        },
        items: const [
          BottomNavigationBarItem(
            icon: Icon(Icons.home),
            label: 'Home / 首页',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.search),
            label: 'Search / 搜索',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.notifications),
            label: 'Alerts / 提醒',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.person),
            label: 'Profile / 我的',
          ),
        ],
      ),
      // Floating action button
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('FAB pressed / 悬浮按钮被点击')),
          );
        },
        icon: const Icon(Icons.add),
        label: const Text('Add / 添加'),
      ),
    );
  }

  Widget _buildSectionHeader(String title) {
    return Padding(
      padding: const EdgeInsets.only(left: 4, right: 4),
      child: Text(
        title,
        style: Theme.of(context).textTheme.titleLarge?.copyWith(
              fontWeight: FontWeight.bold,
            ),
      ),
    );
  }

  Widget _buildColorChip(String label, Color color) {
    return Chip(
      label: Text(label),
      backgroundColor: color,
      labelStyle: TextStyle(
        color: _getContrastColor(color),
        fontWeight: FontWeight.w600,
      ),
      side: BorderSide.none,
    );
  }

  Color _getContrastColor(Color color) {
    // Calculate luminance
    final luminance = color.computeLuminance();
    return luminance > 0.5 ? Colors.black : Colors.white;
  }
}
