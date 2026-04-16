import 'dart:io';
import 'package:home_widget/home_widget.dart';
import 'package:personal_ai_assistant/core/utils/app_logger.dart' as logger;

/// Home screen widget service for managing app widgets.
///
/// Supports:
/// - iOS: WidgetKit widgets
/// - Android: Glance widgets
/// - Updating widget data from Flutter
/// - Background updates
class HomeWidgetService {
  HomeWidgetService._();
  static final HomeWidgetService instance = HomeWidgetService._();

  static const String _nowPlayingWidgetId = 'now_playing_widget';
  static const String _recentUpdatesWidgetId = 'recent_updates_widget';

  /// Initialize the home widget service.
  Future<void> initialize() async {
    if (Platform.isIOS) {
      await HomeWidget.registeriOSWidget(
        _nowPlayingWidgetId,
        configuration: const HomeWidgetBackgroundIOSConfiguration(
          fontFamily: '.SF Pro Text',
        ),
      );
      await HomeWidget.registeriOSWidget(
        _recentUpdatesWidgetId,
        configuration: const HomeWidgetBackgroundIOSConfiguration(
          fontFamily: '.SF Pro Text',
        ),
      );
    }

    logger.AppLogger.debug('[HomeWidgetService] Initialized');
  }

  /// Update the "Now Playing" widget with current episode info.
  Future<void> updateNowPlayingWidget({
    required String title,
    required String podcastName,
    String? imageUrl,
    bool isPlaying = false,
  }) async {
    final data = {
      'title': title,
      'podcastName': podcastName,
      'imageUrl': imageUrl ?? '',
      'isPlaying': isPlaying,
      'updatedAt': DateTime.now().toIso8601String(),
    };

    try {
      await HomeWidget.saveWidgetData(
        _nowPlayingWidgetId,
        data,
      );
      await HomeWidget.updateWidget(
        _nowPlayingWidgetId,
        androidName: 'NowPlayingWidget',
      );
      logger.AppLogger.debug(
        '[HomeWidgetService] Updated now playing widget: $title',
      );
    } catch (e) {
      logger.AppLogger.error(
        '[HomeWidgetService] Failed to update now playing widget: $e',
      );
    }
  }

  /// Update the "Recent Updates" widget with new episodes.
  Future<void> updateRecentUpdatesWidget({
    required List<Map<String, dynamic>> episodes,
  }) async {
    // Limit to 3 most recent episodes
    final recentEpisodes = episodes.take(3).toList();

    final data = {
      'episodes': recentEpisodes,
      'count': recentEpisodes.length,
      'updatedAt': DateTime.now().toIso8601String(),
    };

    try {
      await HomeWidget.saveWidgetData(
        _recentUpdatesWidgetId,
        data,
      );
      await HomeWidget.updateWidget(
        _recentUpdatesWidgetId,
        androidName: 'RecentUpdatesWidget',
      );
      logger.AppLogger.debug(
        '[HomeWidgetService] Updated recent updates widget: ${recentEpisodes.length} episodes',
      );
    } catch (e) {
      logger.AppLogger.error(
        '[HomeWidgetService] Failed to update recent updates widget: $e',
      );
    }
  }

  /// Clear all widget data.
  Future<void> clearAll() async {
    try {
      await HomeWidget.clearWidget(_nowPlayingWidgetId);
      await HomeWidget.clearWidget(_recentUpdatesWidgetId);
      logger.AppLogger.debug('[HomeWidgetService] Cleared all widgets');
    } catch (e) {
      logger.AppLogger.error(
        '[HomeWidgetService] Failed to clear widgets: $e',
      );
    }
  }
}
