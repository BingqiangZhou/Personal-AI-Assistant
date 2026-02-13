import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/features/auth/domain/models/user.dart';
import 'package:personal_ai_assistant/features/auth/presentation/providers/auth_provider.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/profile_stats_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/repositories/podcast_repository.dart';
import 'package:personal_ai_assistant/features/podcast/data/services/podcast_api_service.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/profile/presentation/pages/profile_page.dart';

class _TestAuthNotifier extends AuthNotifier {
  @override
  AuthState build() {
    return AuthState(
      isAuthenticated: true,
      user: User(
        id: '1',
        email: 'test@example.com',
        username: 'tester',
        fullName: 'Test User',
        isVerified: true,
        isActive: true,
      ),
    );
  }
}

class _ThrowingPodcastApiService extends Mock implements PodcastApiService {}

class _ThrowingPodcastRepository extends PodcastRepository {
  _ThrowingPodcastRepository() : super(_ThrowingPodcastApiService());

  @override
  Future<ProfileStatsModel> getProfileStats() async {
    throw Exception('profile stats failed');
  }
}

void main() {
  testWidgets(
    'renders lightweight stats with viewed count from playedEpisodes',
    (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith(_TestAuthNotifier.new),
            profileStatsProvider.overrideWith((ref) async {
              return const ProfileStatsModel(
                totalSubscriptions: 1,
                totalEpisodes: 23,
                summariesGenerated: 12,
                pendingSummaries: 11,
                playedEpisodes: 8,
              );
            }),
          ],
          child: MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: const Scaffold(body: ProfilePage()),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('23'), findsOneWidget);
      expect(find.text('12'), findsOneWidget);
      expect(find.text('8'), findsOneWidget);
      expect(
        find.byKey(const Key('profile_viewed_card_chevron')),
        findsOneWidget,
      );
    },
  );

  testWidgets('shows loading placeholders when profile stats is loading', (
    WidgetTester tester,
  ) async {
    final pending = Completer<ProfileStatsModel?>();

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          authProvider.overrideWith(_TestAuthNotifier.new),
          profileStatsProvider.overrideWith((ref) => pending.future),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(body: ProfilePage()),
        ),
      ),
    );

    await tester.pump();

    expect(find.text('...'), findsNWidgets(3));
  });

  testWidgets('falls back to 0 when profile stats provider returns null', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          authProvider.overrideWith(_TestAuthNotifier.new),
          profileStatsProvider.overrideWith((ref) async => null),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(body: ProfilePage()),
        ),
      ),
    );

    await tester.pumpAndSettle();

    expect(find.text('0'), findsNWidgets(3));
  });

  testWidgets('falls back to 0 when repository throws in provider chain', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          authProvider.overrideWith(_TestAuthNotifier.new),
          podcastRepositoryProvider.overrideWithValue(
            _ThrowingPodcastRepository(),
          ),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(body: ProfilePage()),
        ),
      ),
    );

    await tester.pumpAndSettle();

    expect(find.text('0'), findsNWidgets(3));
  });
}
