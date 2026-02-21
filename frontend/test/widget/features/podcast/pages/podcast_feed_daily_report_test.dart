import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_daily_report_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_state_models.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_feed_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';

void main() {
  group('PodcastFeedPage daily report card', () {
    testWidgets('renders daily report card with items', (tester) async {
      final previousDay = _dateOnlyNowMinus(1);
      await tester.pumpWidget(
        _buildApp(
          feedState: _feedState(),
          dailyReportNotifier: _StaticDailyReportNotifier(
            _reportForDate(previousDay),
          ),
          datesNotifier: _StaticDailyReportDatesNotifier(
            _dates([previousDay, _dateOnlyNowMinus(2)]),
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('daily_report_card')), findsOneWidget);
      expect(find.text('Daily Report'), findsOneWidget);
      expect(find.text('Report summary ${previousDay.day}'), findsOneWidget);
    });

    testWidgets('tapping report item navigates to episode detail', (
      tester,
    ) async {
      final previousDay = _dateOnlyNowMinus(1);
      await tester.pumpWidget(
        _buildApp(
          feedState: _feedState(),
          dailyReportNotifier: _StaticDailyReportNotifier(
            _reportForDate(previousDay),
          ),
          datesNotifier: _StaticDailyReportDatesNotifier(
            _dates([previousDay, _dateOnlyNowMinus(2)]),
          ),
        ),
      );
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(Key('daily_report_item_${previousDay.day}')));
      await tester.pumpAndSettle();

      expect(find.text('detail:${previousDay.day}'), findsOneWidget);
    });

    testWidgets('switching historical date updates report content', (
      tester,
    ) async {
      final previousDay = _dateOnlyNowMinus(1);
      final twoDaysAgo = _dateOnlyNowMinus(2);
      await tester.pumpWidget(
        _buildApp(
          feedState: _feedState(),
          dailyReportNotifier: _SwitchingDailyReportNotifier({
            _dateKey(previousDay): _reportForDate(previousDay),
            _dateKey(twoDaysAgo): _reportForDate(twoDaysAgo),
          }),
          datesNotifier: _StaticDailyReportDatesNotifier(
            _dates([previousDay, twoDaysAgo]),
          ),
          selectedDateNotifier: _FixedSelectedDailyReportDateNotifier(
            previousDay,
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('Report summary ${previousDay.day}'), findsOneWidget);
      await tester.tap(
        find.byKey(const Key('daily_report_date_selector_button')),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('${twoDaysAgo.day}').last);
      await tester.pumpAndSettle();
      await tester.tap(find.text('OK'));
      await tester.pumpAndSettle();

      expect(find.text('Report summary ${twoDaysAgo.day}'), findsOneWidget);
    });

    testWidgets('shows empty state when report is unavailable', (tester) async {
      final previousDay = _dateOnlyNowMinus(1);
      await tester.pumpWidget(
        _buildApp(
          feedState: _feedState(),
          dailyReportNotifier: _StaticDailyReportNotifier(
            const PodcastDailyReportResponse(
              available: false,
              timezone: 'Asia/Shanghai',
              scheduleTimeLocal: '03:30',
              totalItems: 0,
              items: [],
            ),
          ),
          datesNotifier: _StaticDailyReportDatesNotifier(
            _dates([previousDay, _dateOnlyNowMinus(2)]),
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('No daily report available yet'), findsOneWidget);
    });

    testWidgets('shows generate button for previous day and generates report', (
      tester,
    ) async {
      final previousDay = _dateOnlyNowMinus(1);
      final notifier = _GeneratingDailyReportNotifier(
        unavailableDate: previousDay,
        generatedReport: _reportForDate(previousDay),
      );
      await tester.pumpWidget(
        _buildApp(
          feedState: _feedState(),
          dailyReportNotifier: notifier,
          datesNotifier: _StaticDailyReportDatesNotifier(_dates([previousDay])),
          selectedDateNotifier: _FixedSelectedDailyReportDateNotifier(
            previousDay,
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(
        find.byKey(const Key('daily_report_generate_previous_day_button')),
        findsOneWidget,
      );
      await tester.tap(
        find.byKey(const Key('daily_report_generate_previous_day_button')),
      );
      await tester.pumpAndSettle();

      expect(notifier.generateCalls, 1);
      expect(find.text('Report summary ${previousDay.day}'), findsOneWidget);
      await tester.pump(const Duration(seconds: 4));
      await tester.pumpAndSettle();
    });

    testWidgets('does not show generate button for non-previous day', (
      tester,
    ) async {
      final twoDaysAgo = _dateOnlyNowMinus(2);
      await tester.pumpWidget(
        _buildApp(
          feedState: _feedState(),
          dailyReportNotifier: _StaticDailyReportNotifier(
            const PodcastDailyReportResponse(
              available: false,
              timezone: 'Asia/Shanghai',
              scheduleTimeLocal: '03:30',
              totalItems: 0,
              items: [],
            ),
          ),
          datesNotifier: _StaticDailyReportDatesNotifier(_dates([twoDaysAgo])),
          selectedDateNotifier: _FixedSelectedDailyReportDateNotifier(
            twoDaysAgo,
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(
        find.byKey(const Key('daily_report_generate_previous_day_button')),
        findsNothing,
      );
    });
  });
}

Widget _buildApp({
  required PodcastFeedState feedState,
  required DailyReportNotifier dailyReportNotifier,
  required DailyReportDatesNotifier datesNotifier,
  SelectedDailyReportDateNotifier? selectedDateNotifier,
}) {
  final router = GoRouter(
    initialLocation: '/',
    routes: [
      GoRoute(path: '/', builder: (_, __) => const PodcastFeedPage()),
      GoRoute(
        path: '/podcast/episode/detail/:episodeId',
        builder: (context, state) {
          return Scaffold(
            body: Text('detail:${state.pathParameters['episodeId']}'),
          );
        },
      ),
    ],
  );

  return ProviderScope(
    overrides: [
      podcastFeedProvider.overrideWith(
        () => _TestPodcastFeedNotifier(feedState),
      ),
      dailyReportProvider.overrideWith(() => dailyReportNotifier),
      dailyReportDatesProvider.overrideWith(() => datesNotifier),
      if (selectedDateNotifier != null)
        selectedDailyReportDateProvider.overrideWith(
          () => selectedDateNotifier,
        ),
    ],
    child: MaterialApp.router(
      locale: const Locale('en'),
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      routerConfig: router,
    ),
  );
}

PodcastFeedState _feedState() {
  final now = DateTime(2026, 2, 20, 10);
  return PodcastFeedState(
    episodes: [
      PodcastEpisodeModel(
        id: 1,
        subscriptionId: 1,
        title: 'Episode in feed',
        audioUrl: 'https://example.com/1.mp3',
        publishedAt: now,
        createdAt: now,
      ),
    ],
    hasMore: false,
    total: 1,
  );
}

PodcastDailyReportResponse _reportForDate(DateTime date) {
  return PodcastDailyReportResponse(
    available: true,
    reportDate: date,
    timezone: 'Asia/Shanghai',
    scheduleTimeLocal: '03:30',
    generatedAt: DateTime(date.year, date.month, date.day, 3, 30),
    totalItems: 1,
    items: [
      PodcastDailyReportItem(
        episodeId: date.day,
        subscriptionId: 1,
        episodeTitle: 'Episode ${date.day}',
        subscriptionTitle: 'Podcast A',
        oneLineSummary: 'Report summary ${date.day}',
        isCarryover: false,
        episodeCreatedAt: DateTime(date.year, date.month, date.day, 10),
      ),
    ],
  );
}

PodcastDailyReportDatesResponse _dates(List<DateTime> dates) {
  return PodcastDailyReportDatesResponse(
    dates: dates
        .map(
          (item) => PodcastDailyReportDateItem(reportDate: item, totalItems: 1),
        )
        .toList(),
    total: dates.length,
    page: 1,
    size: 30,
    pages: 1,
  );
}

String _dateKey(DateTime? value) {
  if (value == null) {
    return '';
  }
  return '${value.year.toString().padLeft(4, '0')}-${value.month.toString().padLeft(2, '0')}-${value.day.toString().padLeft(2, '0')}';
}

class _TestPodcastFeedNotifier extends PodcastFeedNotifier {
  _TestPodcastFeedNotifier(this._state);

  final PodcastFeedState _state;

  @override
  PodcastFeedState build() => _state;

  @override
  Future<void> loadInitialFeed({
    bool forceRefresh = false,
    bool background = false,
  }) async {}

  @override
  Future<void> loadMoreFeed() async {}
}

class _StaticDailyReportNotifier extends DailyReportNotifier {
  _StaticDailyReportNotifier(this._report);

  final PodcastDailyReportResponse _report;

  @override
  FutureOr<PodcastDailyReportResponse?> build() => _report;

  @override
  Future<PodcastDailyReportResponse?> load({
    DateTime? date,
    bool forceRefresh = false,
  }) async {
    state = AsyncValue.data(_report);
    return _report;
  }
}

class _SwitchingDailyReportNotifier extends DailyReportNotifier {
  _SwitchingDailyReportNotifier(this._reportsByDate);

  final Map<String, PodcastDailyReportResponse> _reportsByDate;

  @override
  FutureOr<PodcastDailyReportResponse?> build() {
    return _reportsByDate['2026-02-20'];
  }

  @override
  Future<PodcastDailyReportResponse?> load({
    DateTime? date,
    bool forceRefresh = false,
  }) async {
    final key = _dateKey(date);
    final selected = _reportsByDate[key] ?? _reportsByDate['2026-02-20'];
    state = AsyncValue.data(selected);
    return selected;
  }
}

class _StaticDailyReportDatesNotifier extends DailyReportDatesNotifier {
  _StaticDailyReportDatesNotifier(this._response);

  final PodcastDailyReportDatesResponse _response;

  @override
  FutureOr<PodcastDailyReportDatesResponse?> build() => _response;

  @override
  Future<PodcastDailyReportDatesResponse?> load({
    int page = 1,
    int size = 30,
    bool forceRefresh = false,
  }) async {
    state = AsyncValue.data(_response);
    return _response;
  }
}

class _FixedSelectedDailyReportDateNotifier
    extends SelectedDailyReportDateNotifier {
  _FixedSelectedDailyReportDateNotifier(this._initial);

  final DateTime? _initial;

  @override
  DateTime? build() => _initial;
}

class _GeneratingDailyReportNotifier extends DailyReportNotifier {
  _GeneratingDailyReportNotifier({
    required this.unavailableDate,
    required this.generatedReport,
  });

  final DateTime unavailableDate;
  final PodcastDailyReportResponse generatedReport;
  int generateCalls = 0;

  @override
  FutureOr<PodcastDailyReportResponse?> build() {
    return PodcastDailyReportResponse(
      available: false,
      reportDate: unavailableDate,
      timezone: 'Asia/Shanghai',
      scheduleTimeLocal: '03:30',
      totalItems: 0,
      items: const [],
    );
  }

  @override
  Future<PodcastDailyReportResponse?> load({
    DateTime? date,
    bool forceRefresh = false,
  }) async {
    return state.value;
  }

  @override
  Future<PodcastDailyReportResponse?> generate({DateTime? date}) async {
    generateCalls += 1;
    state = AsyncValue.data(generatedReport);
    return generatedReport;
  }
}

DateTime _dateOnlyNowMinus(int days) {
  final now = DateTime.now();
  final dateOnly = DateTime(now.year, now.month, now.day);
  return dateOnly.subtract(Duration(days: days));
}
