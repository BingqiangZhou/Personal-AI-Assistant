import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/widgets/adaptive_navigation.dart';

/// Windows兼容性测试页面
///
/// 用于验证Material Design 3自适应布局在Windows平台上的工作状态
class WindowsCompatibilityTestPage extends StatelessWidget {
  const WindowsCompatibilityTestPage({super.key});

  @override
  Widget build(BuildContext context) {
    return ProviderScope(
      child: MaterialApp(
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
        home: const AdaptiveTestPage(),
      ),
    );
  }
}

class AdaptiveTestPage extends ConsumerWidget {
  const AdaptiveTestPage({super.key});

  final List<NavigationDestination> _destinations = const [
    NavigationDestination(
      icon: Icon(Icons.home_outlined),
      selectedIcon: Icon(Icons.home),
      label: 'Home',
    ),
    NavigationDestination(
      icon: Icon(Icons.search_outlined),
      selectedIcon: Icon(Icons.search),
      label: 'Search',
    ),
    NavigationDestination(
      icon: Icon(Icons.settings_outlined),
      selectedIcon: Icon(Icons.settings),
      label: 'Settings',
    ),
  ];

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return AdaptiveNavigation(
      destinations: _destinations,
      selectedIndex: ref.watch(currentTabProvider),
      onDestinationSelected: (index) {
        ref.read(currentTabProvider.notifier).state = index;
      },
      body: _buildCurrentTabContent(ref),
      appBar: AppBar(
        title: const Text('Windows Compatibility Test'),
        backgroundColor: Theme.of(context).colorScheme.surface,
        elevation: 0,
      ),
    );
  }

  Widget _buildCurrentTabContent(WidgetRef ref) {
    final currentIndex = ref.watch(currentTabProvider);

    switch (currentIndex) {
      case 0:
        return _buildHomeTab();
      case 1:
        return _buildSearchTab();
      case 2:
        return _buildSettingsTab();
      default:
        return const Center(child: Text('Tab not found'));
    }
  }

  Widget _buildHomeTab() {
    return SafeResponsiveContainer(
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
                  _buildInfoRow('Device Pixel Ratio', MediaQuery.of(context).devicePixelRatio.toStringAsFixed(2)),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          Text(
            'Responsive Grid Test',
            style: Theme.of(context).textTheme.headlineMedium,
          ),
          const SizedBox(height: 16),
          PlatformResponsiveGrid(
            childAspectRatio: 1.5,
            children: List.generate(12, (index) {
              return Card(
                child: Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(
                        Icons.grid_view,
                        size: 32,
                        color: Theme.of(context).colorScheme.primary,
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Item ${index + 1}',
                        style: Theme.of(context).textTheme.titleSmall,
                      ),
                    ],
                  ),
                ),
              );
            }),
          ),
        ],
      ),
    );
  }

  Widget _buildSearchTab() {
    return SafeResponsiveContainer(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Search Functionality',
            style: Theme.of(context).textTheme.headlineMedium,
          ),
          const SizedBox(height: 16),
          SearchBar(
            hintText: 'Search for items...',
            leading: const Icon(Icons.search),
            trailing: [
              IconButton(
                onPressed: () {
                  // Clear search
                },
                icon: const Icon(Icons.clear),
              ),
            ],
          ),
          const SizedBox(height: 16),
          const Text('Search results will appear here'),
        ],
      ),
    );
  }

  Widget _buildSettingsTab() {
    return SafeResponsiveContainer(
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
                  // Toggle theme
                },
              ),
            ),
          ),
          Card(
            child: ListTile(
              leading: const Icon(Icons.desktop_windows),
              title: const Text('Windows Mode'),
              subtitle: const Text('Enable Windows-specific optimizations'),
              trailing: const Switch(
                value: true,
                onChanged: null,
              ),
            ),
          ),
          Card(
            child: ListTile(
              leading: const Icon(Icons.format_size),
              title: const Text('Responsive Layout'),
              subtitle: const Text('Test different screen sizes'),
              trailing: const Icon(Icons.arrow_forward_ios),
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
}

final currentTabProvider = StateProvider<int>((ref) => 0);