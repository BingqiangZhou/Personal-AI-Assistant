import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../components/desktop_menu_bar.dart';
import '../components/desktop_side_navigation.dart';

class DesktopShell extends ConsumerStatefulWidget {
  const DesktopShell({
    super.key,
    required this.child,
  });

  final Widget child;

  @override
  ConsumerState<DesktopShell> createState() => _DesktopShellState();
}

class _DesktopShellState extends ConsumerState<DesktopShell> {
  final GlobalKey<ScaffoldState> _scaffoldKey = GlobalKey<ScaffoldState>();

  @override
  Widget build(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;
    final state = GoRouterState.of(context);
    final String currentRoute = state.uri.path;

    return Scaffold(
      key: _scaffoldKey,
      appBar: _buildAppBar(context, currentRoute),
      body: Row(
        children: [
          // Side navigation for wider screens
          if (screenWidth > 1200)
            DesktopSideNavigation(
              width: 280,
              currentRoute: currentRoute,
            ),

          // Main content area
          Expanded(
            child: widget.child,
          ),
        ],
      ),
    );
  }

  PreferredSizeWidget? _buildAppBar(BuildContext context, String currentRoute) {
    final screenWidth = MediaQuery.of(context).size.width;

    // Only show app bar on wider screens
    if (screenWidth <= 800) return null;

    return DesktopMenuBar(
      title: _getTitleForRoute(currentRoute),
      currentRoute: currentRoute,
      onMenuPressed: () {
        _scaffoldKey.currentState?.openDrawer();
      },
    );
  }

  String _getTitleForRoute(String route) {
    switch (route) {
      case '/chat':
        return 'AI Assistant';
      case '/knowledge':
        return 'Knowledge Base';
      case '/subscriptions':
        return 'Subscriptions';
      default:
        return 'Personal AI Assistant';
    }
  }
}