import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:riverpod/riverpod.dart';
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
  bool? _lastPlayingState; // Track last playing state to reduce log spam

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

      // Only log when state actually changes
      if (kDebugMode && _lastPlayingState != playbackState.playing) {
        debugPrint('🎵 Playback state changed: ${_lastPlayingState == null ? "initial" : _lastPlayingState! ? "playing" : "paused"} -> ${playbackState.playing ? "playing" : "paused"}');
        _lastPlayingState = playbackState.playing;
      }

      // Always update state regardless of _isPlayingEpisode
      // This ensures UI stays in sync with actual playback state
      state = state.copyWith(
        isPlaying: playbackState.playing,
        isLoading: false,
      );
    });

    // CRITICAL: Use _audioHandler.positionStream instead of AudioService.position
    // AudioService is NOT available on desktop platforms (Windows, macOS, Linux)
    // _audioHandler.positionStream works on both mobile and desktop
    _positionSubscription = _audioHandler.positionStream.listen((position) {
      if (_isDisposed || !ref.mounted) return;

      state = state.copyWith(
        position: position.inMilliseconds,
      );
    });

    _durationSubscription = _audioHandler.mediaItem.listen((mediaItem) {
      if (_isDisposed || !ref.mounted) return;

      // Duration listener as supplementary update (backend duration is used first)
      // Only update if audio stream provides a different or more accurate duration
      if (mediaItem != null) {
        final newDuration = mediaItem.duration?.inMilliseconds ?? 0;

        // Only update if:
        // 1. Current duration is 0 (no backend duration available)
        // 2. New duration is significantly different (>5% difference) and non-zero
        final currentDuration = state.duration;
        final shouldUpdate = currentDuration == 0 ||
                           (newDuration > 0 &&
                            (newDuration - currentDuration).abs() > currentDuration * 0.05);

        if (shouldUpdate && newDuration != currentDuration) {
          if (kDebugMode) {
            debugPrint('🎵 [DURATION UPDATE] ${currentDuration}ms -> ${newDuration}ms (from audio stream)');
          }
          state = state.copyWith(duration: newDuration);
        }
      }
    });

    if (kDebugMode) {
      debugPrint('🎵 Audio listeners set up successfully');
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

      // ===== STEP 2: Set new episode info with duration from backend =====
      debugPrint('📝 Step 2: Setting new episode info');
      // CRITICAL: Backend audioDuration is in SECONDS, convert to MILLISECONDS
      final durationMs = (episode.audioDuration ?? 0) * 1000;
      debugPrint('  📊 Using backend duration: ${episode.audioDuration}s = ${durationMs}ms');
      state = state.copyWith(
        currentEpisode: episode,
        isLoading: true,
        isPlaying: false, // Keep false until actually playing
        duration: durationMs, // Convert seconds to milliseconds
        error: null,
      );

      // ===== STEP 3: Set new episode with metadata =====
      // CRITICAL: Use setEpisode() to properly set MediaItem, validate artUri, and load audio
      // artUri validation is built into setEpisode() - only http/https URLs are accepted
      debugPrint('🔄 Step 3: Setting new episode with metadata');
      debugPrint('  📊 Backend duration already set: ${state.duration}ms');
      debugPrint('  🖼️ Image URL: ${episode.imageUrl ?? "NULL"}');

      try {
        await _audioHandler.setEpisode(
          id: episode.id.toString(),
          url: episode.audioUrl,
          title: episode.title,
          artist: episode.subscriptionTitle ?? 'Unknown Podcast',
          artUri: episode.imageUrl, // Will be validated inside setEpisode()
          autoPlay: false, // We'll manually start playback after restoring position/speed
        );
        debugPrint('  ✅ Episode loaded successfully');
      } catch (loadError) {
        debugPrint('  ❌ Failed to load episode: $loadError');
        throw Exception('Failed to load audio: $loadError');
      }

      if (!ref.mounted || _isDisposed) return;

      // ===== STEP 4: Restore playback position =====
      if (episode.playbackPosition != null && episode.playbackPosition! > 0) {
        debugPrint('⏩ Step 4: Seeking to saved position: ${episode.playbackPosition}ms');
        try {
          await _audioHandler.seek(Duration(milliseconds: episode.playbackPosition!));
          debugPrint('  ✅ Seek completed');
        } catch (e) {
          debugPrint('  ⚠️ Seek error: $e');
        }
      }

      if (!ref.mounted || _isDisposed) return;

      // ===== STEP 5: Restore playback rate =====
      if (savedPlaybackRate != 1.0) {
        debugPrint('⚙️ Step 5: Restoring playback rate: ${savedPlaybackRate}x');
        try {
          await _audioHandler.setSpeed(savedPlaybackRate);
          debugPrint('  ✅ Playback rate restored');
        } catch (e) {
          debugPrint('  ⚠️ Failed to restore playback rate: $e');
        }
      }

      // ===== STEP 6: Start playback =====
      debugPrint('▶️ Step 6: Starting playback');
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
    // Mark as subscribing
    state = state.copyWith(
      subscribingFeedUrls: {...state.subscribingFeedUrls, feedUrl},
    );

    try {
      final subscription = await _repository.addSubscription(
        feedUrl: feedUrl,
        categoryIds: categoryIds,
      );

      // Refresh the list
      await refreshSubscriptions();

      // Remove from subscribing set (refreshSubscriptions resets state, so we need to add it back)
      state = state.copyWith(
        subscribingFeedUrls: state.subscribingFeedUrls.where((url) => url != feedUrl).toSet(),
      );

      return subscription;
    } catch (error) {
      // Remove from subscribing set
      state = state.copyWith(
        subscribingFeedUrls: state.subscribingFeedUrls.where((url) => url != feedUrl).toSet(),
      );
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