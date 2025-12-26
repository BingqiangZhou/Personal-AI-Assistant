import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../../../podcast/presentation/pages/podcast_feed_page.dart';
import '../../../podcast/presentation/pages/podcast_list_page.dart';
import '../../../assistant/presentation/pages/assistant_chat_page.dart';
import '../../../knowledge/presentation/pages/knowledge_base_page.dart';
import '../../../profile/presentation/pages/profile_page.dart';

/// Material Design 3自适应主页
///
/// 使用AdaptiveScaffoldWrapper实现跨设备响应式导航
class HomePage extends ConsumerStatefulWidget {
  final Widget? child;
  final int? initialTab;

  const HomePage({super.key, this.child, this.initialTab});

  @override
  ConsumerState<HomePage> createState() => _HomePageState();
}

class _HomePageState extends ConsumerState<HomePage> {
  late int _currentIndex;

  /// 导航目的地配置
  List<NavigationDestination> _buildDestinations(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return [
      NavigationDestination(
        icon: Icon(Icons.home_outlined),
        selectedIcon: Icon(Icons.home),
        label: l10n.nav_feed,
      ),
      NavigationDestination(
        icon: Icon(Icons.podcasts_outlined),
        selectedIcon: Icon(Icons.podcasts),
        label: l10n.nav_podcast,
      ),
      NavigationDestination(
        icon: Icon(Icons.chat_outlined),
        selectedIcon: Icon(Icons.chat),
        label: l10n.nav_chat,
      ),
      NavigationDestination(
        icon: Icon(Icons.folder_outlined),
        selectedIcon: Icon(Icons.folder),
        label: l10n.nav_knowledge,
      ),
      NavigationDestination(
        icon: Icon(Icons.person_outline),
        selectedIcon: Icon(Icons.person),
        label: l10n.nav_profile,
      ),
    ];
  }

  @override
  void initState() {
    super.initState();
    _currentIndex = widget.initialTab ?? 0; // Default to Feed/信息流 (index 0)
  }

  @override
  Widget build(BuildContext context) {
    // 如果有子组件，直接显示（用于内嵌页面）
    if (widget.child != null) {
      return Scaffold(
        appBar: null, // 移除顶部标题栏
        body: widget.child,
        floatingActionButton: _buildFloatingActionButton(),
      );
    }

    // 主导航布局 - 使用自定义的Material Design 3自适应导航
    return CustomAdaptiveNavigation(
      key: const ValueKey('home_custom_adaptive_navigation'),
      destinations: _buildDestinations(context),
      selectedIndex: _currentIndex,
      onDestinationSelected: _handleNavigation,
      appBar: null, // 移除顶部标题栏
      floatingActionButton: _buildFloatingActionButton(),
      body: _buildTabContent(context, _currentIndex),
    );
  }

  /// 构建浮动操作按钮
  Widget? _buildFloatingActionButton() {
    return null;
  }

  /// 处理导航选择
  void _handleNavigation(int index) {
    if (_currentIndex != index) {
      setState(() {
        _currentIndex = index;
      });
    }
  }

  /// 构建当前标签页内容
  Widget _buildTabContent(BuildContext context, int index) {
    return _buildCurrentTabContent();
  }

  /// 构建当前标签页内容（保持原有逻辑）
  Widget _buildCurrentTabContent() {
    switch (_currentIndex) {
      case 0:
        return const PodcastFeedPage();
      case 1:
        return const PodcastListPage();
      case 2:
        return const AssistantChatPage();
      case 3:
        return const KnowledgeBasePage();
      case 4:
        return const ProfilePage();
      default:
        return const Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                Icons.error_outline,
                size: 64,
                color: Colors.grey,
              ),
              SizedBox(height: 16),
              Text(
                'Page Not Found',
                style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.w500,
                  color: Colors.grey,
                ),
              ),
              SizedBox(height: 8),
              Text(
                'Please select a valid tab from the navigation',
                style: TextStyle(
                  fontSize: 14,
                  color: Colors.grey,
                ),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        );
    }
  }
}