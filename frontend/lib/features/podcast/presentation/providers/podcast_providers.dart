import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:riverpod/riverpod.dart';
import 'package:audioplayers/audioplayers.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../../../../core/providers/core_providers.dart';
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
  AudioPlayer? _player;
  late PodcastRepository _repository;
  bool _isDisposed = false;

  @override
  AudioPlayerState build() {
    _repository = ref.read(podcastRepositoryProvider);
    _isDisposed = false;

    // Initialize audio player
    _initializePlayer();

    // Clean up when provider is disposed
    ref.onDispose(() {
      _isDisposed = true;
      _player?.dispose();
    });

    return const AudioPlayerState();
  }

  Future<void> _initializePlayer() async {
    if (_player != null || _isDisposed) return;

    try {
      _player = AudioPlayer();

      // Listen to player state changes
      _player!.onPlayerStateChanged.listen((playerState) {
        if (_isDisposed || !ref.mounted) return;

        if (kDebugMode) {
          debugPrint('🎵 Player state changed: $playerState');
        }

        ProcessingState processingState;
        switch (playerState) {
          case PlayerState.stopped:
          case PlayerState.completed:
            processingState = ProcessingState.completed;
            break;
          case PlayerState.playing:
            processingState = ProcessingState.ready;
            break;
          case PlayerState.paused:
            processingState = ProcessingState.ready;
            break;
          case PlayerState.disposed:
            processingState = ProcessingState.idle;
            break;
        }

        state = state.copyWith(
          isPlaying: playerState == PlayerState.playing,
          isLoading: false,
          processingState: processingState,
        );
      });

      // Listen to position changes
      _player!.onPositionChanged.listen((position) {
        if (_isDisposed || !ref.mounted) return;

        state = state.copyWith(
          position: position.inMilliseconds,
        );
      });

      // Listen to duration changes
      _player!.onDurationChanged.listen((duration) {
        if (_isDisposed || !ref.mounted) return;

        if (duration != null) {
          if (kDebugMode) {
            debugPrint('🎵 Duration updated: ${duration.inMilliseconds}ms');
          }

          state = state.copyWith(
            duration: duration.inMilliseconds,
          );
        }
      });

      if (kDebugMode) {
        debugPrint('🎵 AudioPlayers player initialized successfully');
      }
    } catch (error) {
      debugPrint('Failed to initialize audio player: $error');
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(
          error: 'Failed to initialize audio player: $error'
        );
      }
      rethrow;
    }
  }

  Future<void> playEpisode(PodcastEpisodeModel episode) async {
    try {
      // Debug: Print audio URL
      debugPrint('🎵 Playing episode: ${episode.title}');
      debugPrint('🎵 Audio URL: ${episode.audioUrl}');

      // Check if provider is still mounted
      if (!ref.mounted || _isDisposed) return;

      // Ensure player is initialized
      await _initializePlayer();

      // Check again after async operation
      if (!ref.mounted || _isDisposed) return;

      // Set current episode and loading state
      state = state.copyWith(
        currentEpisode: episode,
        isLoading: true,
        error: null,
      );

      // Load audio with error handling
      debugPrint('🎵 Loading audio from URL...');
      try {
        await _player!.setSource(UrlSource(episode.audioUrl));
        debugPrint('🎵 Audio loaded successfully');
      } catch (loadError) {
        debugPrint('❌ Failed to load audio: $loadError');
        throw Exception('Failed to load audio: $loadError');
      }

      // Check again after async operation
      if (!ref.mounted || _isDisposed) return;

      // Seek to saved position if available
      if (episode.playbackPosition != null && episode.playbackPosition! > 0) {
        await _player!.seek(Duration(milliseconds: episode.playbackPosition!));
      }

      // Start playback
      debugPrint('🎵 Starting playback...');
      try {
        await _player!.play(UrlSource(episode.audioUrl));
        debugPrint('🎵 Playback started successfully');
      } catch (playError) {
        debugPrint('❌ Failed to start playback: $playError');
        throw Exception('Failed to start playback: $playError');
      }

      // Update final state
      state = state.copyWith(
        isPlaying: true,
        isLoading: false,
        position: episode.playbackPosition ?? 0,
      );

      // Update playback state on server (non-blocking)
      if (ref.mounted && !_isDisposed) {
        _updatePlaybackStateOnServer().catchError((error) {
          debugPrint('⚠️ Server update failed: $error');
        });
      }
    } catch (error) {
      debugPrint('❌ Failed to play episode: $error');

      // Update error state
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(
          isLoading: false,
          error: 'Failed to play audio: $error',
        );
      }
    }
  }

  Future<void> pause() async {
    if (_player == null || _isDisposed) return;

    try {
      await _player!.pause();
      if (ref.mounted && !_isDisposed) {
        await _updatePlaybackStateOnServer();
      }
    } catch (error) {
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(
          error: error.toString()
        );
      }
    }
  }

  Future<void> resume() async {
    if (_player == null || _isDisposed) return;

    try {
      await _player!.resume();
      if (ref.mounted && !_isDisposed) {
        await _updatePlaybackStateOnServer();
      }
    } catch (error) {
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(
          error: error.toString()
        );
      }
    }
  }

  Future<void> seekTo(int position) async {
    if (_player == null || _isDisposed) return;

    try {
      await _player!.seek(Duration(milliseconds: position));
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(
          position: position
        );
        await _updatePlaybackStateOnServer();
      }
    } catch (error) {
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(
          error: error.toString()
        );
      }
    }
  }

  Future<void> setPlaybackRate(double rate) async {
    if (_player == null || _isDisposed) return;

    try {
      await _player!.setPlaybackRate(rate);
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(
          playbackRate: rate
        );
        await _updatePlaybackStateOnServer();
      }
    } catch (error) {
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(
          error: error.toString()
        );
      }
    }
  }

  Future<void> stop() async {
    if (_player == null || _isDisposed) return;

    try {
      await _player!.stop();
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(
          currentEpisode: null,
          isPlaying: false,
          position: 0,
        );
      }
    } catch (error) {
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(
          error: error.toString()
        );
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
    state = state.copyWith(isLoading: true);

    try {
      final response = await _repository.listEpisodes(
        subscriptionId: subscriptionId,
        page: page,
        size: size,
        isPlayed: status == 'played' ? true : (status == 'unplayed' ? false : null),
      );

      state = state.copyWith(
        episodes: page == 1 ? response.episodes : [...state.episodes, ...response.episodes],
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