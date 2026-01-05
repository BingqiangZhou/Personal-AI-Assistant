import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:riverpod/riverpod.dart';
import 'package:audio_service/audio_service.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../../../../main.dart' as main_app;
import 'audio_handler.dart';

import '../../../../core/providers/core_providers.dart';
import '../../../../core/network/exceptions/network_exceptions.dart';
import '../../../auth/presentation/providers/auth_provider.dart';
import '../../data/models/podcast_episode_model.dart';
import '../../data/models/podcast_playback_model.dart';
import '../../data/models/podcast_subscription_model.dart';
import '../../data/models/audio_player_state_model.dart';
import '../../data/models/podcast_state_models.dart';
import '../../data/repositories/podcast_repository.dart';
import '../../data/services/podcast_api_service.dart';

// === API Service & Repository Providers ===

final podcastApiServiceProvider = Provider<PodcastApiService>((ref) {
  final dio = ref.watch(dioClientProvider).dio;
  return PodcastApiService(dio);
});

final podcastRepositoryProvider = Provider<PodcastRepository>((ref) {
  final apiService = ref.watch(podcastApiServiceProvider);
  return PodcastRepository(apiService);
});

final audioPlayerProvider = NotifierProvider<AudioPlayerNotifier, AudioPlayerState>(AudioPlayerNotifier.new);

class AudioPlayerNotifier extends Notifier<AudioPlayerState> {
  late PodcastRepository _repository;
  bool _isDisposed = false;
  bool _isPlayingEpisode = false;
  StreamSubscription? _playerStateSubscription;
  StreamSubscription? _positionSubscription;
  StreamSubscription? _durationSubscription;

  PodcastAudioHandler get _audioHandler => main_app.audioHandler as PodcastAudioHandler;

  @override
  AudioPlayerState build() {
    _repository = ref.read(podcastRepositoryProvider);
    _isDisposed = false;

    _setupListeners();

    ref.onDispose(() {
      _isDisposed = true;
      _playerStateSubscription?.cancel();
      _positionSubscription?.cancel();
      _durationSubscription?.cancel();
    });

    return const AudioPlayerState();
  }

  void _setupListeners() {
    if (_isDisposed) return;

    _playerStateSubscription = _audioHandler.playbackState.listen((playbackState) {
      if (_isDisposed || !ref.mounted) return;

      if (kDebugMode) {
        debugPrint('🎵 Playback state changed: playing=${playbackState.playing}');
      }

      // Always update state regardless of _isPlayingEpisode
      // This ensures UI stays in sync with actual playback state
      state = state.copyWith(
        isPlaying: playbackState.playing,
        isLoading: false,
      );
    });

    _positionSubscription = AudioService.position.listen((position) {
      if (_isDisposed || !ref.mounted) return;

      state = state.copyWith(
        position: position.inMilliseconds,
      );
    });

    _durationSubscription = _audioHandler.mediaItem.listen((mediaItem) {
      if (_isDisposed || !ref.mounted) return;

      // CRITICAL: Always update duration, even if null (to handle initial state)
      // When duration is extracted from audio stream, it will be non-null and update correctly
      if (mediaItem != null) {
        final newDuration = mediaItem.duration?.inMilliseconds ?? 0;
        // Only update if duration changed (avoid unnecessary rebuilds)
        if (state.duration != newDuration) {
          if (kDebugMode) {
            debugPrint('🎵 [DURATION LISTENER] Duration changing: ${state.duration}ms -> ${newDuration}ms');
            debugPrint('   MediaItem.id: ${mediaItem.id}');
            debugPrint('   MediaItem.title: ${mediaItem.title}');
            debugPrint('   MediaItem.duration: ${mediaItem.duration}');
            debugPrint('   state.currentEpisode?.id: ${state.currentEpisode?.id}');
          }
          state = state.copyWith(duration: newDuration);
          if (kDebugMode) {
            debugPrint('   ✅ State updated: state.duration = ${state.duration}ms');
            debugPrint('   ✅ Formatted duration: ${state.formattedDuration}');
          }
        }
      } else {
        if (kDebugMode) {
          debugPrint('⚠️ [DURATION LISTENER] mediaItem is null, skipping update');
        }
      }
    });

    if (kDebugMode) {
      debugPrint('🎵 AudioService listeners set up successfully');
    }
  }

  Future<void> playEpisode(PodcastEpisodeModel episode) async {
    if (_isPlayingEpisode) {
      debugPrint('⚠️ playEpisode already in progress, ignoring duplicate call');
      return;
    }

    _isPlayingEpisode = true;

    try {
      debugPrint('🎵 ===== playEpisode called =====');
      debugPrint('🎵 Episode ID: ${episode.id}');
      debugPrint('🎵 Episode Title: ${episode.title}');
      debugPrint('🎵 Audio URL: ${episode.audioUrl}');
      debugPrint('🎵 Subscription ID: ${episode.subscriptionId}');

      if (!ref.mounted || _isDisposed) {
        _isPlayingEpisode = false;
        return;
      }

      final savedPlaybackRate = state.playbackRate;

      // ===== STEP 1: Pause current playback instead of stop =====
      // Using pause() instead of stop() to avoid clearing the audio source
      // This maintains the media session state better
      debugPrint('⏸️ Step 1: Pausing current playback');
      try {
        await _audioHandler.pause();
        debugPrint('  ✅ Paused');
      } catch (e) {
        debugPrint('  ⚠️ Pause error (ignorable): $e');
      }

      state = const AudioPlayerState().copyWith(
        playbackRate: savedPlaybackRate,
      );

      if (!ref.mounted || _isDisposed) return;

      // ===== STEP 2: Set new episode info (DON'T mark as playing yet) =====
      debugPrint('📝 Step 2: Setting new episode info');
      state = state.copyWith(
        currentEpisode: episode,
        isLoading: true,
        isPlaying: false, // Keep false until actually playing
        error: null,
      );

      // ===== STEP 3: Set MediaItem FIRST (before audio source) =====
      // CRITICAL: Android MediaSession needs metadata BEFORE content loads
      // This ensures the notification displays correct information when audio loads
      // IMPORTANT: Don't set duration here - let just_audio extract it from the audio stream
      debugPrint('🔄 Step 3: Setting MediaItem for system controls (before audio source)');
      debugPrint('  📊 Episode.audioDuration: ${episode.audioDuration}ms (this value is NOT used, let audio stream extract duration)');
      _audioHandler.mediaItem.add(MediaItem(
        id: episode.id.toString(),
        title: episode.title,
        artist: episode.subscriptionTitle ?? 'Unknown Podcast',
        artUri: episode.imageUrl != null ? Uri.parse(episode.imageUrl!) : null,
        // Don't set duration - let just_audio extract it from audio stream
        duration: null,
      ));
      debugPrint('  ✅ MediaItem set with duration=null (will be updated when audio loads)');

      // Small delay to ensure MediaItem is set before audio loads
      await Future.delayed(const Duration(milliseconds: 50));

      if (!ref.mounted || _isDisposed) return;

      // ===== STEP 4: Set new audio source AFTER MediaItem =====
      debugPrint('🔄 Step 4: Setting new audio source');
      try {
        await _audioHandler.setAudioSource(episode.audioUrl);
        debugPrint('  ✅ Source set successfully');
      } catch (loadError) {
        debugPrint('  ❌ Failed to set source: $loadError');
        throw Exception('Failed to load audio: $loadError');
      }

      if (!ref.mounted || _isDisposed) return;

      // ===== STEP 5: Restore playback position =====
      if (episode.playbackPosition != null && episode.playbackPosition! > 0) {
        debugPrint('⏩ Step 5: Seeking to saved position: ${episode.playbackPosition}ms');
        try {
          await _audioHandler.seek(Duration(milliseconds: episode.playbackPosition!));
          debugPrint('  ✅ Seek completed');
        } catch (e) {
          debugPrint('  ⚠️ Seek error: $e');
        }
      }

      if (!ref.mounted || _isDisposed) return;

      // ===== STEP 6: Restore playback rate =====
      if (savedPlaybackRate != 1.0) {
        debugPrint('⚙️ Step 6: Restoring playback rate: ${savedPlaybackRate}x');
        try {
          await _audioHandler.setSpeed(savedPlaybackRate);
          debugPrint('  ✅ Playback rate restored');
        } catch (e) {
          debugPrint('  ⚠️ Failed to restore playback rate: $e');
        }
      }

      // ===== STEP 7: Start playback =====
      debugPrint('▶️ Step 7: Starting playback');
      try {
        await _audioHandler.play();
        debugPrint('  ✅ Playback started');

        if (ref.mounted && !_isDisposed) {
          state = state.copyWith(
            isPlaying: true,
            isLoading: false,
            position: episode.playbackPosition ?? 0,
            playbackRate: savedPlaybackRate,
          );
        }
      } catch (playError) {
        debugPrint('  ❌ Failed to start playback: $playError');
        _isPlayingEpisode = false;
        throw Exception('Failed to start playback: $playError');
      }

      debugPrint('🎵 ===== playEpisode completed =====');

      // Update playback state on server (non-blocking)
      if (ref.mounted && !_isDisposed) {
        _updatePlaybackStateOnServer().catchError((error) {
          debugPrint('⚠️ Server update failed: $error');
        });
      }

      // Release the lock
      _isPlayingEpisode = false;
    } catch (error) {
      debugPrint('❌ ===== Failed to play episode =====');
      debugPrint('❌ Episode ID: ${episode.id}');
      debugPrint('❌ Audio URL: ${episode.audioUrl}');
      debugPrint('❌ Error: $error');

      // Release the lock on error
      _isPlayingEpisode = false;

      // Update error state
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(
          isLoading: false,
          isPlaying: false, // Ensure playing is false on error
          error: 'Failed to play audio: $error',
        );
      }
    }
  }

  Future<void> pause() async {
    if (_isDisposed) return;

    try {
      debugPrint('🔴 pause() called, current isPlaying: ${state.isPlaying}');

      // IMPORTANT: Don't manually update state here - let the playbackState listener handle it
      // The listener will update the state when playbackState.playing changes
      // This avoids race conditions where manual state gets overwritten

      await _audioHandler.pause();
      debugPrint('🔴 AudioHandler.pause() completed, waiting for playbackState listener to update UI');

      if (ref.mounted && !_isDisposed) {
        await _updatePlaybackStateOnServer();
      }
    } catch (error) {
      debugPrint('❌ pause() error: $error');
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(error: error.toString());
      }
    }
  }

  Future<void> resume() async {
    if (_isDisposed) return;

    try {
      debugPrint('🟢 resume() called, current isPlaying: ${state.isPlaying}');

      // IMPORTANT: Don't manually update state here - let the playbackState listener handle it
      // The listener will update the state when playbackState.playing changes
      // This avoids race conditions where manual state gets overwritten

      await _audioHandler.play();
      debugPrint('🟢 AudioHandler.play() completed, waiting for playbackState listener to update UI');

      if (ref.mounted && !_isDisposed) {
        await _updatePlaybackStateOnServer();
      }
    } catch (error) {
      debugPrint('❌ resume() error: $error');
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(isPlaying: false, error: error.toString());
      }
    }
  }

  Future<void> seekTo(int position) async {
    if (_isDisposed) return;

    try {
      await _audioHandler.seek(Duration(milliseconds: position));
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(position: position);
        await _updatePlaybackStateOnServer();
      }
    } catch (error) {
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(error: error.toString());
      }
    }
  }

  Future<void> setPlaybackRate(double rate) async {
    if (_isDisposed) return;

    try {
      await _audioHandler.setSpeed(rate);
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(playbackRate: rate);
        await _updatePlaybackStateOnServer();
      }
    } catch (error) {
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(error: error.toString());
      }
    }
  }

  Future<void> stop() async {
    if (_isDisposed) return;

    try {
      await _audioHandler.stop();
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(
          clearCurrentEpisode: true,
          isPlaying: false,
          position: 0,
        );
      }
    } catch (error) {
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(error: error.toString());
      }
    }
  }

  void setExpanded(bool expanded) {
    if (ref.mounted && !_isDisposed) {
      state = state.copyWith(
        isExpanded: expanded
      );
    }
  }

  Future<void> _updatePlaybackStateOnServer() async {
    if (_isDisposed) return;

    final episode = state.currentEpisode;
    if (episode == null) return;

    try {
      await _repository.updatePlaybackProgress(
        episodeId: episode.id,
        position: (state.position / 1000).round(), // Convert to seconds
        isPlaying: state.isPlaying,
        playbackRate: state.playbackRate,
      );
    } catch (error) {
      // Log more detailed error for debugging
      debugPrint('⚠️ Failed to update playback state on server: $error');
      debugPrint('📍 Episode ID: ${episode.id}');
      debugPrint('📍 Position: ${state.position}ms (${(state.position / 1000).round()}s)');
      debugPrint('📍 Is Playing: ${state.isPlaying}');
      debugPrint('📍 Playback Rate: ${state.playbackRate}');

      // Check if it's an authentication error
      if (error.toString().contains('401') || error.toString().contains('authentication')) {
        debugPrint('🔑 Authentication error - user may need to log in again');
      }

      // Don't update the UI state for server errors - continue playback
    }
  }
}

final podcastSubscriptionProvider = NotifierProvider<PodcastSubscriptionNotifier, PodcastSubscriptionState>(PodcastSubscriptionNotifier.new);

class PodcastSubscriptionNotifier extends Notifier<PodcastSubscriptionState> {
  late PodcastRepository _repository;

  @override
  PodcastSubscriptionState build() {
    _repository = ref.read(podcastRepositoryProvider);
    return const PodcastSubscriptionState();
  }

  Future<void> loadSubscriptions({
    int page = 1,
    int size = 10,
    int? categoryId,
    String? status,
  }) async {
    state = state.copyWith(isLoading: true, error: null);

    try {
      final response = await _repository.listSubscriptions(
        page: page,
        size: size,
        categoryId: categoryId,
        status: status,
      );

      state = state.copyWith(
        subscriptions: response.subscriptions,
        hasMore: page < response.pages,
        nextPage: page < response.pages ? page + 1 : null,
        currentPage: page,
        total: response.total,
        isLoading: false,
      );
    } catch (error) {
      state = state.copyWith(
        isLoading: false,
        error: error.toString(),
      );
      rethrow;
    }
  }

  Future<void> loadMoreSubscriptions({
    int? categoryId,
    String? status,
  }) async {
    if (state.isLoadingMore || !state.hasMore) return;

    state = state.copyWith(isLoadingMore: true);

    try {
      final response = await _repository.listSubscriptions(
        page: state.nextPage ?? 1,
        size: 10,
        categoryId: categoryId,
        status: status,
      );

      state = state.copyWith(
        subscriptions: [...state.subscriptions, ...response.subscriptions],
        hasMore: (state.nextPage ?? 1) < response.pages,
        nextPage: (state.nextPage ?? 1) < response.pages ? (state.nextPage ?? 1) + 1 : null,
        currentPage: state.nextPage ?? 1,
        total: response.total,
        isLoadingMore: false,
      );
    } catch (error) {
      state = state.copyWith(
        isLoadingMore: false,
        error: error.toString(),
      );
    }
  }

  Future<void> refreshSubscriptions({
    int? categoryId,
    String? status,
  }) async {
    state = const PodcastSubscriptionState();
    await loadSubscriptions(
      page: 1,
      size: 10,
      categoryId: categoryId,
      status: status,
    );
  }

  Future<PodcastSubscriptionModel> addSubscription({
    required String feedUrl,
    List<int>? categoryIds,
  }) async {
    try {
      final subscription = await _repository.addSubscription(
        feedUrl: feedUrl,
        categoryIds: categoryIds,
      );

      // Refresh the list
      await refreshSubscriptions();

      return subscription;
    } catch (error) {
      rethrow;
    }
  }

  Future<void> addSubscriptionsBatch({
    required List<String> feedUrls,
    List<int>? categoryIds,
  }) async {
    try {
      await _repository.addSubscriptionsBatch(
        feedUrls: feedUrls,
        categoryIds: categoryIds,
      );

      // Refresh the list
      await refreshSubscriptions();
    } catch (error) {
      rethrow;
    }
  }

  Future<void> deleteSubscription(int subscriptionId) async {
    try {
      await _repository.deleteSubscription(subscriptionId);

      // Refresh the list
      await refreshSubscriptions();
    } catch (error) {
      rethrow;
    }
  }

  Future<PodcastSubscriptionBulkDeleteResponse> bulkDeleteSubscriptions({
    required List<int> subscriptionIds,
  }) async {
    try {
      // Debug log
      debugPrint('🗑️ Bulk delete request: subscriptionIds=$subscriptionIds');
      debugPrint('🗑️ Subscription IDs type: ${subscriptionIds.runtimeType}');

      final response = await _repository.bulkDeleteSubscriptions(
        subscriptionIds: subscriptionIds,
      );

      debugPrint('✅ Bulk delete success: ${response.successCount} deleted, ${response.failedCount} failed');

      // Refresh the list
      await refreshSubscriptions();

      return response;
    } catch (error) {
      debugPrint('❌ Bulk delete failed: $error');
      rethrow;
    }
  }

  Future<void> refreshSubscription(int subscriptionId) async {
    try {
      await _repository.refreshSubscription(subscriptionId);

      // Refresh the list
      await refreshSubscriptions();
    } catch (error) {
      rethrow;
    }
  }

  Future<void> reparseSubscription(int subscriptionId, bool forceAll) async {
    try {
      await _repository.reparseSubscription(subscriptionId, forceAll);

      // Refresh the list
      await refreshSubscriptions();
    } catch (error) {
      rethrow;
    }
  }
}

final podcastFeedProvider = NotifierProvider<PodcastFeedNotifier, PodcastFeedState>(PodcastFeedNotifier.new);

class PodcastFeedNotifier extends Notifier<PodcastFeedState> {
  late PodcastRepository _repository;

  @override
  PodcastFeedState build() {
    _repository = ref.read(podcastRepositoryProvider);
    return const PodcastFeedState();
  }

  Future<void> loadInitialFeed() async {
    state = state.copyWith(isLoading: true, error: null);

    try {
      final response = await _repository.getPodcastFeed(
        page: 1,
        pageSize: 20,
      );

      state = state.copyWith(
        episodes: response.items,
        hasMore: response.hasMore,
        nextPage: response.nextPage,
        total: response.total,
        isLoading: false,
      );
    } catch (error) {
      debugPrint('❌ 加载最新内容失败: $error');

      // Check if this is an authentication error
      if (error is AuthenticationException) {
        debugPrint('🔓 认证失败，触发认证状态检查');
        // Trigger auth status check to update state and redirect to login
        ref.read(authProvider.notifier).checkAuthStatus();
      }

      state = state.copyWith(
        isLoading: false,
        error: '加载最新内容失败: ${error.toString()}',
      );
    }
  }

  Future<void> loadMoreFeed() async {
    final currentState = state;
    if (currentState.isLoadingMore || !currentState.hasMore) return;

    state = state.copyWith(isLoadingMore: true);

    try {
      final response = await _repository.getPodcastFeed(
        page: currentState.nextPage ?? 1,
        pageSize: 20,
      );

      state = state.copyWith(
        episodes: [...state.episodes, ...response.items],
        hasMore: response.hasMore,
        nextPage: response.nextPage,
        total: response.total,
        isLoadingMore: false,
      );
    } catch (error) {
      debugPrint('❌ 加载更多内容失败: $error');

      // Check if this is an authentication error
      if (error is AuthenticationException) {
        debugPrint('🔓 认证失败，触发认证状态检查');
        // Trigger auth status check to update state and redirect to login
        ref.read(authProvider.notifier).checkAuthStatus();
      }

      state = state.copyWith(
        isLoadingMore: false,
        error: '加载更多内容失败: ${error.toString()}',
      );
    }
  }

  Future<void> refreshFeed() async {
    state = state.copyWith(
      episodes: [],
      hasMore: true,
      nextPage: null,
      total: 0,
    );
    await loadInitialFeed();
  }

  void clearError() {
    state = state.copyWith(error: null);
  }
}

final podcastSearchProvider = AsyncNotifierProvider<PodcastSearchNotifier, PodcastEpisodeListResponse>(PodcastSearchNotifier.new);

class PodcastSearchNotifier extends AsyncNotifier<PodcastEpisodeListResponse> {
  late PodcastRepository _repository;

  @override
  FutureOr<PodcastEpisodeListResponse> build() {
    _repository = ref.read(podcastRepositoryProvider);
    return Future.value(const PodcastEpisodeListResponse(
      episodes: [],
      total: 0,
      page: 1,
      size: 20,
      pages: 0,
      subscriptionId: 0,
    ));
  }

  Future<void> searchPodcasts({
    required String query,
    String searchIn = 'all',
    int page = 1,
    int size = 20,
  }) async {
    if (query.trim().isEmpty) {
      state = AsyncValue.data(const PodcastEpisodeListResponse(
        episodes: [],
        total: 0,
        page: 1,
        size: 20,
        pages: 0,
        subscriptionId: 0,
      ));
      return;
    }

    state = const AsyncValue.loading();

    try {
      final response = await _repository.searchPodcasts(
        query: query,
        searchIn: searchIn,
        page: page,
        size: size,
      );
      state = AsyncValue.data(response);
    } catch (error, stackTrace) {
      state = AsyncValue.error(error, stackTrace);
    }
  }
}

// === Stats Provider ===
final podcastStatsProvider = FutureProvider<PodcastStatsResponse?>((ref) async {
  final repository = ref.read(podcastRepositoryProvider);
  try {
    return await repository.getStats();
  } catch (error) {
    return null;
  }
});

// === Episode Detail Provider ===
final episodeDetailProvider = FutureProvider.family<PodcastEpisodeDetailResponse?, int>((ref, episodeId) async {
  final repository = ref.read(podcastRepositoryProvider);
  try {
    return await repository.getEpisode(episodeId);
  } catch (error) {
    debugPrint('Failed to load episode detail: $error');
    return null;
  }
});

// For Riverpod 3.0.3, we need to use a different approach for family providers
// Let's use a simple Notifier and pass the subscriptionId through methods
final podcastEpisodesProvider = NotifierProvider<PodcastEpisodesNotifier, PodcastEpisodesState>(PodcastEpisodesNotifier.new);

class PodcastEpisodesNotifier extends Notifier<PodcastEpisodesState> {
  late PodcastRepository _repository;

  @override
  PodcastEpisodesState build() {
    _repository = ref.read(podcastRepositoryProvider);
    return const PodcastEpisodesState();
  }

  // Load episodes for a specific subscription
  Future<void> loadEpisodesForSubscription({
    required int subscriptionId,
    int page = 1,
    int size = 20,
    String? status,
  }) async {
    debugPrint('📋 Loading episodes for subscription $subscriptionId, page $page');

    // When loading first page, clear existing episodes immediately to avoid showing old data
    if (page == 1) {
      debugPrint('📋 Clearing old episodes and showing loading state');
      state = state.copyWith(
        isLoading: true,
        episodes: [], // Clear immediately
        error: null,
      );
    } else {
      state = state.copyWith(isLoading: true);
    }

    try {
      final response = await _repository.listEpisodes(
        subscriptionId: subscriptionId,
        page: page,
        size: size,
        isPlayed: status == 'played' ? true : (status == 'unplayed' ? false : null),
      );

      debugPrint('📋 Loaded ${response.episodes.length} episodes for subscription $subscriptionId');

      // Debug: Log item_link data for first few episodes
      if (response.episodes.isNotEmpty) {
        for (var i = 0; i < response.episodes.length && i < 3; i++) {
          final ep = response.episodes[i];
          debugPrint('🔗 Episode ${i + 1}: "${ep.title}"');
          debugPrint('   - itemLink: ${ep.itemLink ?? "NULL"}');
          debugPrint('   - audioUrl: ${ep.audioUrl}');
        }
      }

      state = state.copyWith(
        episodes: page == 1 ? response.episodes : [...state.episodes, ...response.episodes],
        hasMore: page < response.pages,
        nextPage: page < response.pages ? page + 1 : null,
        currentPage: page,
        total: response.total,
        isLoading: false,
      );
    } catch (error) {
      debugPrint('❌ Failed to load episodes: $error');
      state = state.copyWith(
        isLoading: false,
        error: error.toString(),
      );
    }
  }

  // Load more episodes for the current subscription
  Future<void> loadMoreEpisodesForSubscription({
    required int subscriptionId,
  }) async {
    final currentState = state;
    if (currentState.isLoadingMore || !currentState.hasMore) return;

    state = state.copyWith(isLoadingMore: true);

    try {
      final response = await _repository.listEpisodes(
        subscriptionId: subscriptionId,
        page: currentState.nextPage ?? 1,
        size: 20,
      );

      state = state.copyWith(
        episodes: [...state.episodes, ...response.episodes],
        hasMore: state.nextPage != null && state.nextPage! < response.pages,
        nextPage: state.nextPage != null && state.nextPage! < response.pages ? state.nextPage! + 1 : null,
        isLoadingMore: false,
      );
    } catch (error) {
      state = state.copyWith(
        isLoadingMore: false,
        error: error.toString(),
      );
    }
  }

  // Refresh episodes for a specific subscription
  Future<void> refreshEpisodesForSubscription({
    required int subscriptionId,
    String? status,
  }) async {
    state = state.copyWith(episodes: []);
    await loadEpisodesForSubscription(
      subscriptionId: subscriptionId,
      status: status,
    );
  }
}

// Note: Models are defined in separate files. This file only contains providers.