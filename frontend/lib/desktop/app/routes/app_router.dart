import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../features/auth/view/login_screen.dart';
import '../../../features/auth/view/register_screen.dart';
import '../../../features/assistant/view/chat_screen.dart';
import '../../../features/assistant/view/chat_list_screen.dart';
import '../../../features/knowledge/view/knowledge_list_screen.dart';
import '../../../features/knowledge/view/knowledge_detail_screen.dart';
import '../../../features/subscription/view/subscription_list_screen.dart';
import '../../widgets/layouts/desktop_shell.dart';

// Router provider
final appRouterProvider = Provider<GoRouter>((ref) {
  return GoRouter(
    initialLocation: '/login',
    debugLogDiagnostics: true,
    routes: [
      // Authentication routes
      GoRoute(
        path: '/login',
        name: 'login',
        builder: (context, state) => const LoginScreen(),
      ),
      GoRoute(
        path: '/register',
        name: 'register',
        builder: (context, state) => const RegisterScreen(),
      ),

      // Main application routes with shell
      ShellRoute(
        builder: (context, state, child) => DesktopShell(child: child),
        routes: [
          GoRoute(
            path: '/chat',
            name: 'chat',
            builder: (context, state) => const ChatScreen(),
          ),
          GoRoute(
            path: '/knowledge',
            name: 'knowledge',
            builder: (context, state) => const KnowledgeListScreen(),
          ),
          GoRoute(
            path: '/knowledge/:id',
            name: 'knowledge_detail',
            builder: (context, state) {
              final id = state.pathParameters['id']!;
              return KnowledgeDetailScreen(knowledgeId: id);
            },
          ),
          GoRoute(
            path: '/subscriptions',
            name: 'subscriptions',
            builder: (context, state) => const SubscriptionListScreen(),
          ),
        ],
      ),

      // Home redirect
      GoRoute(
        path: '/',
        name: 'home',
        redirect: (context, state) => '/chat',
      ),
    ],
    errorBuilder: (context, state) => Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(
              Icons.error_outline,
              size: 64,
              color: Colors.red,
            ),
            const SizedBox(height: 16),
            Text(
              'Page not found',
              style: Theme.of(context).textTheme.headlineMedium,
            ),
            const SizedBox(height: 8),
            Text(
              state.error.toString(),
              style: Theme.of(context).textTheme.bodyMedium,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            ElevatedButton(
              onPressed: () => context.go('/chat'),
              child: const Text('Go Home'),
            ),
          ],
        ),
      ),
    ),
  );
});