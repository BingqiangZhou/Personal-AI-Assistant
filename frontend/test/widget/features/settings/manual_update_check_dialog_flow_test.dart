import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/services/app_update_service.dart';
import 'package:personal_ai_assistant/features/settings/presentation/providers/app_update_provider.dart';
import 'package:personal_ai_assistant/features/settings/presentation/widgets/update_dialog.dart';
import 'package:personal_ai_assistant/shared/models/github_release.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('ManualUpdateCheckDialog flow', () {
    testWidgets('does not stack dialogs on repeated check triggers', (
      tester,
    ) async {
      final service = _FakeAppUpdateService(
        release: null,
        delay: const Duration(milliseconds: 250),
      );

      await tester.pumpWidget(_buildHost(service: service));

      final context = tester.element(find.byType(ElevatedButton));
      ManualUpdateCheckDialog.show(context);
      ManualUpdateCheckDialog.show(context);
      ManualUpdateCheckDialog.show(context);
      await tester.pump();

      expect(find.byType(ManualUpdateCheckDialog), findsOneWidget);

      await tester.pumpAndSettle();
      expect(find.text("You're up to date"), findsOneWidget);

      await tester.tap(find.text('OK'));
      await tester.pumpAndSettle();
    });

    testWidgets('redirects to AppUpdateDialog when update is available', (
      tester,
    ) async {
      final service = _FakeAppUpdateService(release: _buildRelease());

      await tester.pumpWidget(_buildHost(service: service));

      await tester.tap(find.text('Open Check Dialog'));
      await tester.pump();
      await tester.pumpAndSettle();

      expect(find.text('Release Notes'), findsOneWidget);
      expect(find.text('Highlights'), findsOneWidget);
      expect(
        find.text('A new version is available. Would you like to update now?'),
        findsNothing,
      );

      await tester.tap(find.text('Later'));
      await tester.pumpAndSettle();
    });

    testWidgets('shows up-to-date state when no update is available', (
      tester,
    ) async {
      final service = _FakeAppUpdateService(release: null);

      await tester.pumpWidget(_buildHost(service: service));

      await tester.tap(find.text('Open Check Dialog'));
      await tester.pump();
      await tester.pumpAndSettle();

      expect(find.text("You're up to date"), findsOneWidget);

      await tester.tap(find.text('OK'));
      await tester.pumpAndSettle();
    });

    testWidgets('shows error state and retry button when check fails', (
      tester,
    ) async {
      final service = _FakeAppUpdateService(error: Exception('network error'));

      await tester.pumpWidget(_buildHost(service: service));

      await tester.tap(find.text('Open Check Dialog'));
      await tester.pump();
      await tester.pumpAndSettle();

      expect(find.text('Check Failed'), findsOneWidget);
      expect(find.text('Try Again'), findsOneWidget);

      await tester.tap(find.text('Close'));
      await tester.pumpAndSettle();
    });
  });
}

Widget _buildHost({required AppUpdateService service}) {
  return ProviderScope(
    overrides: [appUpdateServiceProvider.overrideWith((ref) => service)],
    child: MaterialApp(
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: Scaffold(
        body: Builder(
          builder: (context) {
            return Center(
              child: ElevatedButton(
                onPressed: () {
                  ManualUpdateCheckDialog.show(context);
                },
                child: const Text('Open Check Dialog'),
              ),
            );
          },
        ),
      ),
    ),
  );
}

class _FakeAppUpdateService extends AppUpdateService {
  _FakeAppUpdateService({this.release, this.error, this.delay = Duration.zero});

  final GitHubRelease? release;
  final Object? error;
  final Duration delay;

  @override
  Future<GitHubRelease?> checkForUpdates({
    bool forceRefresh = false,
    bool includePrerelease = false,
  }) async {
    if (delay > Duration.zero) {
      await Future<void>.delayed(delay);
    }
    if (error != null) {
      throw error!;
    }
    return release;
  }

  @override
  Future<void> clearSkippedVersion() async {}
}

GitHubRelease _buildRelease() {
  return GitHubRelease(
    tagName: 'v0.5.4',
    name: 'Release v0.5.4',
    version: '0.5.4',
    body: '## Highlights\n- Direct open detailed update dialog',
    prerelease: false,
    draft: false,
    createdAt: DateTime(2026, 2, 12),
    publishedAt: DateTime(2026, 2, 12),
    htmlUrl: 'https://github.com/example/repo/releases/tag/v0.5.4',
    assets: const [],
  );
}
