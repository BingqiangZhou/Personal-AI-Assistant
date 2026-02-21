import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/network/exceptions/network_exceptions.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_daily_report_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/repositories/podcast_repository.dart';
import 'package:personal_ai_assistant/features/podcast/data/services/podcast_api_service.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';

void main() {
  group('DailyReport providers', () {
    test('loads daily report and reuses fresh cache', () async {
      final repository = _FakePodcastRepository();
      final container = ProviderContainer(
        overrides: [podcastRepositoryProvider.overrideWithValue(repository)],
      );
      addTearDown(container.dispose);

      final notifier = container.read(dailyReportProvider.notifier);
      await notifier.load(forceRefresh: false);
      await notifier.load(forceRefresh: false);

      expect(repository.dailyReportCalls, 1);
      expect(container.read(dailyReportProvider).value?.available, isTrue);
    });

    test('switching selected date loads historical daily report', () async {
      final repository = _FakePodcastRepository();
      final container = ProviderContainer(
        overrides: [podcastRepositoryProvider.overrideWithValue(repository)],
      );
      addTearDown(container.dispose);

      final notifier = container.read(dailyReportProvider.notifier);
      await notifier.load(forceRefresh: false);
      container
          .read(selectedDailyReportDateProvider.notifier)
          .setDate(DateTime(2026, 2, 19));
      await notifier.load(date: DateTime(2026, 2, 19), forceRefresh: true);

      final switched = container.read(dailyReportProvider).value;

      expect(switched?.reportDate, DateTime(2026, 2, 19));
      expect(repository.lastDailyReportDate, DateTime(2026, 2, 19));
    });

    test('force refresh bypasses cache for daily report', () async {
      final repository = _FakePodcastRepository();
      final container = ProviderContainer(
        overrides: [podcastRepositoryProvider.overrideWithValue(repository)],
      );
      addTearDown(container.dispose);

      final notifier = container.read(dailyReportProvider.notifier);
      await notifier.load(forceRefresh: false);
      await notifier.load(forceRefresh: true);

      expect(repository.dailyReportCalls, 2);
    });

    test('daily report dates provider loads and caches', () async {
      final repository = _FakePodcastRepository();
      final container = ProviderContainer(
        overrides: [podcastRepositoryProvider.overrideWithValue(repository)],
      );
      addTearDown(container.dispose);

      final notifier = container.read(dailyReportDatesProvider.notifier);
      await notifier.load(forceRefresh: false);
      await notifier.load(forceRefresh: false);

      expect(repository.dailyReportDatesCalls, 1);
      expect(container.read(dailyReportDatesProvider).value?.dates.length, 2);
    });

    test('generate daily report updates state and refreshes dates', () async {
      final repository = _FakePodcastRepository();
      final container = ProviderContainer(
        overrides: [podcastRepositoryProvider.overrideWithValue(repository)],
      );
      addTearDown(container.dispose);

      final notifier = container.read(dailyReportProvider.notifier);
      final targetDate = DateTime(2026, 2, 20);
      final result = await notifier.generate(date: targetDate);

      expect(result?.available, isTrue);
      expect(result?.reportDate, DateTime(2026, 2, 20));
      expect(container.read(dailyReportProvider).value?.reportDate, targetDate);
      expect(repository.generateDailyReportCalls, 1);
      expect(repository.lastGeneratedReportDate, targetDate);
      expect(repository.lastGeneratedReportRebuild, false);
      expect(repository.dailyReportDatesCalls, 1);
    });

    test('generate daily report passes rebuild flag', () async {
      final repository = _FakePodcastRepository();
      final container = ProviderContainer(
        overrides: [podcastRepositoryProvider.overrideWithValue(repository)],
      );
      addTearDown(container.dispose);

      final notifier = container.read(dailyReportProvider.notifier);
      await notifier.generate(date: DateTime(2026, 2, 20), rebuild: true);

      expect(repository.generateDailyReportCalls, 1);
      expect(repository.lastGeneratedReportRebuild, true);
    });

    test('generate daily report rethrows on failure', () async {
      final repository = _FailingGeneratePodcastRepository();
      final container = ProviderContainer(
        overrides: [podcastRepositoryProvider.overrideWithValue(repository)],
      );
      addTearDown(container.dispose);

      final notifier = container.read(dailyReportProvider.notifier);

      await expectLater(
        () => notifier.generate(date: DateTime(2026, 2, 20)),
        throwsA(isA<NetworkException>()),
      );
    });
  });
}

class _FakePodcastRepository extends PodcastRepository {
  _FakePodcastRepository() : super(PodcastApiService(Dio()));

  int dailyReportCalls = 0;
  int dailyReportDatesCalls = 0;
  int generateDailyReportCalls = 0;
  DateTime? lastDailyReportDate;
  DateTime? lastGeneratedReportDate;
  bool? lastGeneratedReportRebuild;

  @override
  Future<PodcastDailyReportResponse> getDailyReport({DateTime? date}) async {
    dailyReportCalls += 1;
    lastDailyReportDate = date;

    final reportDate = date == null
        ? DateTime(2026, 2, 20)
        : DateTime(date.year, date.month, date.day);
    return PodcastDailyReportResponse(
      available: true,
      reportDate: reportDate,
      timezone: 'Asia/Shanghai',
      scheduleTimeLocal: '03:30',
      generatedAt: DateTime(2026, 2, 21, 3, 30),
      totalItems: 1,
      items: [
        PodcastDailyReportItem(
          episodeId: reportDate.day,
          subscriptionId: 1,
          episodeTitle: 'Episode ${reportDate.day}',
          subscriptionTitle: 'Podcast',
          oneLineSummary: 'Summary ${reportDate.day}',
          isCarryover: false,
          episodeCreatedAt: DateTime(2026, 2, reportDate.day, 10),
        ),
      ],
    );
  }

  @override
  Future<PodcastDailyReportDatesResponse> getDailyReportDates({
    int page = 1,
    int size = 30,
  }) async {
    dailyReportDatesCalls += 1;
    return PodcastDailyReportDatesResponse(
      dates: [
        PodcastDailyReportDateItem(
          reportDate: DateTime(2026, 2, 20),
          totalItems: 2,
        ),
        PodcastDailyReportDateItem(
          reportDate: DateTime(2026, 2, 19),
          totalItems: 1,
        ),
      ],
      total: 2,
      page: page,
      size: size,
      pages: 1,
    );
  }

  @override
  Future<PodcastDailyReportResponse> generateDailyReport({
    DateTime? date,
    bool rebuild = false,
  }) async {
    generateDailyReportCalls += 1;
    lastGeneratedReportDate = date;
    lastGeneratedReportRebuild = rebuild;
    final reportDate = date == null
        ? DateTime(2026, 2, 20)
        : DateTime(date.year, date.month, date.day);
    return PodcastDailyReportResponse(
      available: true,
      reportDate: reportDate,
      timezone: 'Asia/Shanghai',
      scheduleTimeLocal: '03:30',
      generatedAt: DateTime(2026, 2, 21, 4, 0),
      totalItems: 1,
      items: [
        PodcastDailyReportItem(
          episodeId: reportDate.day,
          subscriptionId: 1,
          episodeTitle: 'Episode ${reportDate.day}',
          subscriptionTitle: 'Podcast',
          oneLineSummary: 'Generated summary ${reportDate.day}',
          isCarryover: false,
          episodeCreatedAt: DateTime(2026, 2, reportDate.day, 10),
        ),
      ],
    );
  }
}

class _FailingGeneratePodcastRepository extends _FakePodcastRepository {
  @override
  Future<PodcastDailyReportResponse> generateDailyReport({
    DateTime? date,
    bool rebuild = false,
  }) async {
    throw const NetworkException('Server error');
  }
}
