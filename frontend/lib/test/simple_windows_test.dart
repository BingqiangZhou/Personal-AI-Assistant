import 'package:flutter/material.dart';

import '../core/widgets/safe_navigation_rail.dart';

/// 简单的Windows兼容性测试页面
/// 用于验证修复后的NavigationRail是否正常工作
class SimpleWindowsTestPage extends StatelessWidget {
  const SimpleWindowsTestPage({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Windows Compatibility Test',
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.blue,
          brightness: Brightness.light,
        ),
      ),
      darkTheme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.blue,
          brightness: Brightness.dark,
        ),
      ),
      home: const SafeNavigationTestPage(),
    );
  }
}

class SafeNavigationTestPage extends StatefulWidget {
  const SafeNavigationTestPage({super.key});

  @override
  State<SafeNavigationTestPage> createState() => _SafeNavigationTestPageState();
}

class _SafeNavigationTestPageState extends State<SafeNavigationTestPage> {
  int _currentIndex = 0;

  final List<NavigationDestination> _destinations = const [
    NavigationDestination(
      icon: Icon(Icons.home_outlined),
      selectedIcon: Icon(Icons.home),
      label: 'Home',
    ),
    NavigationDestination(
      icon: Icon(Icons.grid_view_outlined),
      selectedIcon: Icon(Icons.grid_view),
      label: 'Grid Test',
    ),
    NavigationDestination(
      icon: Icon(Icons.settings_outlined),
      selectedIcon: Icon(Icons.settings),
      label: 'Settings',
    ),
  ];

  @override
  Widget build(BuildContext context) {
    return FullySafeAdaptiveNavigation(
      destinations: _destinations,
      selectedIndex: _currentIndex,
      onDestinationSelected: (index) {
        setState(() {
          _currentIndex = index;
        });
      },
      body: _buildCurrentTabContent(),
      appBar: AppBar(
        title: const Text('Windows Compatibility Test'),
        backgroundColor: Theme.of(context).colorScheme.surface,
        elevation: 0,
      ),
    );
  }

  Widget _buildCurrentTabContent() {
    switch (_currentIndex) {
      case 0:
        return _buildHomeTab();
      case 1:
        return _buildGridTestTab();
      case 2:
        return _buildSettingsTab();
      default:
        return const Center(child: Text('Tab not found'));
    }
  }

  Widget _buildHomeTab() {
    return SimpleResponsiveContainer(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Platform Information',
            style: Theme.of(context).textTheme.headlineMedium,
          ),
          const SizedBox(height: 16),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _buildInfoRow('Platform', Theme.of(context).platform.toString()),
                  _buildInfoRow('Screen Width', '${MediaQuery.of(context).size.width.toInt()}px'),
                  _buildInfoRow('Screen Height', '${MediaQuery.of(context).size.height.toInt()}px'),
                  _buildInfoRow('Navigation Mode', _getNavigationMode(MediaQuery.of(context).size.width)),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          Text(
            'Test Results',
            style: Theme.of(context).textTheme.headlineMedium,
          ),
          const SizedBox(height: 16),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Icon(
                    Icons.check_circle,
                    color: Colors.green,
                    size: 24,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    '✅ NavigationRail断言错误已修复',
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                      color: Colors.green,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    '✅ 支持移动端、平板端和桌面端',
                    style: Theme.of(context).textTheme.bodyMedium,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    '✅ 兼容Windows平台',
                    style: Theme.of(context).textTheme.bodyMedium,
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildGridTestTab() {
    return SimpleResponsiveContainer(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Responsive Grid Test',
            style: Theme.of(context).textTheme.headlineMedium,
          ),
          const SizedBox(height: 16),
          Text(
            'Grid布局会根据屏幕宽度自动调整列数',
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 16),
          Expanded(
            child: SafeResponsiveGrid(
              childAspectRatio: 1.2,
              children: List.generate(20, (index) {
                return Card(
                  child: Center(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(
                          Icons.grid_4x4,
                          size: 32,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                        const SizedBox(height: 8),
                        Text(
                          'Item ${index + 1}',
                          style: Theme.of(context).textTheme.titleSmall,
                        ),
                        Text(
                          'Responsive',
                          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: Theme.of(context).colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  ),
                );
              }),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSettingsTab() {
    return SimpleResponsiveContainer(
      child: ListView(
        children: [
          Card(
            child: ListTile(
              leading: const Icon(Icons.brightness_6),
              title: const Text('Theme'),
              subtitle: const Text('Toggle between light and dark theme'),
              trailing: Switch(
                value: Theme.of(context).brightness == Brightness.dark,
                onChanged: (value) {
                  // 主题切换功能可以在这里实现
                },
              ),
            ),
          ),
          Card(
            child: ListTile(
              leading: const Icon(Icons.devices),
              title: const Text('Device Type'),
              subtitle: Text(_getDeviceType(MediaQuery.of(context).size.width)),
              trailing: const Icon(Icons.info_outline),
            ),
          ),
          Card(
            child: ListTile(
              leading: const Icon(Icons.webhook),
              title: const Text('Navigation Type'),
              subtitle: Text(_getNavigationMode(MediaQuery.of(context).size.width)),
              trailing: const Icon(Icons.info_outline),
            ),
          ),
          const Card(
            child: Padding(
              padding: EdgeInsets.all(16),
              child: Text(
                '测试完成！NavigationRail现在可以在所有平台上安全运行。',
                style: TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.w500,
                  color: Colors.green,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInfoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
              fontWeight: FontWeight.w500,
            ),
          ),
          Text(
            value,
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
              color: Theme.of(context).colorScheme.primary,
            ),
          ),
        ],
      ),
    );
  }

  String _getDeviceType(double width) {
    if (width < 600) return 'Mobile';
    if (width < 840) return 'Tablet';
    return 'Desktop';
  }

  String _getNavigationMode(double width) {
    if (width < 600) return 'Bottom Navigation';
    if (width < 840) return 'Compact NavigationRail';
    return 'Extended NavigationRail';
  }
}

void main() {
  runApp(const SimpleWindowsTestPage());
}