import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../features/splash/presentation/pages/splash_page.dart';
import '../../features/auth/presentation/pages/login_page.dart';
import '../../features/auth/presentation/pages/register_page.dart';
import '../../features/auth/presentation/pages/auth_test_page.dart';
import '../../features/auth/presentation/pages/auth_verify_page.dart';
import '../../features/auth/presentation/pages/forgot_password_page.dart';
import '../../features/auth/presentation/pages/reset_password_page.dart';
import '../../features/home/presentation/pages/home_page.dart';
import '../../features/assistant/presentation/pages/assistant_chat_page.dart';
import '../../features/podcast/presentation/pages/podcast_list_page.dart';
import '../../features/podcast/presentation/pages/podcast_player_page.dart';
import '../../features/podcast/presentation/pages/podcast_episodes_page.dart';
import '../../features/podcast/presentation/pages/podcast_episode_detail_page.dart';
import '../../features/podcast/presentation/navigation/podcast_navigation.dart';
import '../../features/settings/presentation/pages/settings_page.dart';

final appRouterProvider = Provider<GoRouter>((ref) {
  return GoRouter(
    initialLocation: '/home',
    debugLogDiagnostics: true,
    routes: [
      // Splash
      GoRoute(
        path: '/splash',
        name: 'splash',
        builder: (context, state) => const SplashPage(),
      ),

      // Auth
      GoRoute(
        path: '/login',
        name: 'login',
        builder: (context, state) => const LoginPage(),
      ),
      GoRoute(
        path: '/register',
        name: 'register',
        builder: (context, state) => const RegisterPage(),
      ),
      GoRoute(
        path: '/auth-test',
        name: 'auth-test',
        builder: (context, state) => const AuthTestPage(),
      ),
      GoRoute(
        path: '/auth-verify',
        name: 'auth-verify',
        builder: (context, state) => const AuthVerifyPage(),
      ),
      GoRoute(
        path: '/forgot-password',
        name: 'forgot-password',
        builder: (context, state) => const ForgotPasswordPage(),
      ),
      GoRoute(
        path: '/reset-password',
        name: 'reset-password',
        builder: (context, state) {
          final token = state.uri.queryParameters['token'];
          return ResetPasswordPage(token: token);
        },
      ),

      // Main app with bottom navigation
      GoRoute(
        path: '/home',
        name: 'home',
        builder: (context, state) => const HomePage(),
        routes: [
          GoRoute(
            path: 'assistant',
            name: 'assistant',
            builder: (context, state) => const AssistantChatPage(),
          ),
        ],
      ),

      // Podcast routes (no bottom nav)
      GoRoute(
        path: '/podcast',
        name: 'podcast',
        builder: (context, state) => const PodcastListPage(),
        routes: [
          // 1. 订阅的单集列表: /podcast/episodes/1
          GoRoute(
            path: 'episodes/:subscriptionId',
            name: 'podcastEpisodes',
            builder: (context, state) {
              final args = PodcastEpisodesPageArgs.extractFromState(state);
              if (args == null) {
                return const Scaffold(
                  body: Center(child: Text('Invalid navigation arguments')),
                );
              }
              return PodcastEpisodesPage(
                subscriptionId: args.subscriptionId,
                podcastTitle: args.podcastTitle,
                subscription: args.subscription,
              );
            },
          ),
          // 2. 单集详情: /podcast/episodes/1/2
          GoRoute(
            path: 'episodes/:subscriptionId/:episodeId',
            name: 'episodeDetail',
            builder: (context, state) {
              final args = PodcastEpisodeDetailPageArgs.extractFromState(state);
              if (args == null) {
                return const Scaffold(
                  body: Center(child: Text('Invalid navigation arguments')),
                );
              }
              return PodcastEpisodeDetailPage(episodeId: args.episodeId);
            },
          ),
          // 3. 播放器: /podcast/player/1?subscriptionId=1
          GoRoute(
            path: 'player/:episodeId',
            name: 'episodePlayer',
            builder: (context, state) {
              final args = PodcastPlayerPageArgs.extractFromState(state);
              if (args == null) {
                return const Scaffold(
                  body: Center(child: Text('Invalid navigation arguments')),
                );
              }
              return PodcastPlayerPage(args: args);
            },
          ),
        ],
      ),

      // Knowledge routes
      GoRoute(
        path: '/knowledge',
        name: 'knowledge',
        builder: (context, state) => const HomePage(initialTab: 3),
      ),

      // Profile routes
      GoRoute(
        path: '/profile',
        name: 'profile',
        builder: (context, state) => const HomePage(initialTab: 4),
        routes: [
          GoRoute(
            path: 'settings',
            name: 'settings',
            builder: (context, state) => const SettingsPage(),
          ),
        ],
      ),
    ],

    // Redirect logic
    redirect: (context, state) {
      // TODO: Implement auth state checking
      // For now, always allow access
      return null;
    },

    // Error handling
    errorBuilder: (context, state) => ErrorPage(error: state.error),
  );
});

class ErrorPage extends StatelessWidget {
  final Exception? error;

  const ErrorPage({super.key, this.error});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Error'),
      ),
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
            const Text(
              'An error occurred',
              style: TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              error?.toString() ?? 'Unknown error',
              textAlign: TextAlign.center,
              style: const TextStyle(color: Colors.grey),
            ),
            const SizedBox(height: 32),
            ElevatedButton(
              onPressed: () => context.go('/splash'),
              child: const Text('Go to Home'),
            ),
          ],
        ),
      ),
    );
  }
}