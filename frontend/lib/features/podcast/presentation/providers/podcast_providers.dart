import 'dart:async';

import 'package:equatable/equatable.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
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
import 'package:json_annotation/json_annotation.dart';

part 'podcast_providers.g.dart';

// === API Service & Repository Providers ===

final podcastApiServiceProvider = Provider<PodcastApiService>((ref) {
  final dio = ref.watch(dioClientProvider).dio;
  return PodcastApiService(dio);
});

final podcastRepositoryProvider = Provider<PodcastRepository>((ref) {
  final apiService = ref.watch(podcastApiServiceProvider);
  return PodcastRepository(apiService);
});

// === Audio Player Provider ===

@riverpod
class AudioPlayerNotifier extends _$AudioPlayerNotifier {
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
      _player!.onPlayerStateChanged.listen((state) {
        if (_isDisposed || !ref.mounted) return;

        if (kDebugMode) {
          debugPrint('🎵 Player state changed: $state');
        }

        ProcessingState processingState;
        switch (state) {
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

        this.state = this.state.copyWith(
          isPlaying: state == PlayerState.playing,
          isLoading: false,
          processingState: processingState,
        );
      });

      // Listen to position changes
      _player!.onPositionChanged.listen((position) {
        if (_isDisposed || !ref.mounted) return;

        // if (kDebugMode) {
        //   debugPrint('🎵 Position updated: ${position.inMilliseconds}ms');
        // }

        this.state = this.state.copyWith(
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

          this.state = this.state.copyWith(
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
        state = state.copyWith(error: 'Failed to initialize audio player: $error');
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
        state = state.copyWith(error: error.toString());
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
        state = state.copyWith(error: error.toString());
      }
    }
  }

  Future<void> seekTo(int position) async {
    if (_player == null || _isDisposed) return;

    try {
      await _player!.seek(Duration(milliseconds: position));
      if (ref.mounted && !_isDisposed) {
        await _updatePlaybackStateOnServer();
      }
    } catch (error) {
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(error: error.toString());
      }
    }
  }

  Future<void> setPlaybackRate(double rate) async {
    if (_player == null || _isDisposed) return;

    try {
      await _player!.setPlaybackRate(rate);
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
        state = state.copyWith(error: error.toString());
      }
    }
  }

  void setExpanded(bool expanded) {
    if (ref.mounted && !_isDisposed) {
      state = state.copyWith(isExpanded: expanded);
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

// === Subscription Providers ===
@riverpod
class PodcastSubscriptionNotifier extends _$PodcastSubscriptionNotifier {
  late PodcastRepository _repository;

  @override
  AsyncValue<PodcastSubscriptionListResponse> build() {
    _repository = ref.read(podcastRepositoryProvider);
    return const AsyncValue.loading();
  }

  Future<void> loadSubscriptions({
    int page = 1,
    int size = 20,
    int? categoryId,
    String? status,
  }) async {
    state = const AsyncValue.loading();

    try {
      final response = await _repository.listSubscriptions(
        page: page,
        size: size,
        categoryId: categoryId,
        status: status,
      );
      state = AsyncValue.data(response);
    } catch (error, stackTrace) {
      state = AsyncValue.error(error, stackTrace);
    }
  }

  Future<PodcastSubscriptionModel> addSubscription({
    required String feedUrl,
    String? customName,
    List<int>? categoryIds,
  }) async {
    try {
      final subscription = await _repository.addSubscription(
        feedUrl: feedUrl,
        customName: customName,
        categoryIds: categoryIds,
      );

      // Refresh the list
      await loadSubscriptions();

      return subscription;
    } catch (error) {
      rethrow;
    }
  }

  Future<void> deleteSubscription(int subscriptionId) async {
    try {
      await _repository.deleteSubscription(subscriptionId);

      // Refresh the list
      await loadSubscriptions();
    } catch (error) {
      rethrow;
    }
  }

  Future<void> refreshSubscription(int subscriptionId) async {
    try {
      await _repository.refreshSubscription(subscriptionId);

      // Refresh the list
      await loadSubscriptions();
    } catch (error) {
      rethrow;
    }
  }

  Future<void> reparseSubscription(int subscriptionId, bool forceAll) async {
    try {
      await _repository.reparseSubscription(subscriptionId, forceAll);

      // Refresh the list
      await loadSubscriptions();
    } catch (error) {
      rethrow;
    }
  }
}

// === Feed Providers ===
@riverpod
class PodcastFeedNotifier extends _$PodcastFeedNotifier {
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
    } catch (error, stackTrace) {
      debugPrint('❌ 加载最新内容失败: $error');
      state = state.copyWith(
        isLoading: false,
        error: '加载最新内容失败: ${error.toString()}',
      );
    }
  }

  Future<void> loadMoreFeed() async {
    if (state.isLoadingMore || !state.hasMore) return;

    state = state.copyWith(isLoadingMore: true);

    try {
      final response = await _repository.getPodcastFeed(
        page: state.nextPage ?? 1,
        pageSize: 20,
      );

      state = state.copyWith(
        episodes: [...state.episodes, ...response.items],
        hasMore: response.hasMore,
        nextPage: response.nextPage,
        total: response.total,
        isLoadingMore: false,
      );
    } catch (error, stackTrace) {
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

// === Search Provider ===
@riverpod
class PodcastSearchNotifier extends _$PodcastSearchNotifier {
  late PodcastRepository _repository;

  @override
  AsyncValue<PodcastEpisodeListResponse> build() {
    _repository = ref.read(podcastRepositoryProvider);
    return const AsyncValue.data(PodcastEpisodeListResponse(
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
      state = const AsyncValue.data(PodcastEpisodeListResponse(
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
@riverpod
Future<PodcastStatsResponse?> podcastStatsProvider(Ref ref) async {
  final repository = ref.read(podcastRepositoryProvider);
  try {
    return await repository.getStats();
  } catch (error) {
    return null;
  }
}

// === Episode Detail Provider ===
@riverpod
Future<PodcastEpisodeDetailResponse?> episodeDetailProvider(Ref ref, int episodeId) async {
  final repository = ref.read(podcastRepositoryProvider);
  try {
    return await repository.getEpisode(episodeId);
  } catch (error) {
    debugPrint('Failed to load episode detail: $error');
    return null;
  }
}

// === Episode Episodes Provider ===
@riverpod
class PodcastEpisodesNotifier extends _$PodcastEpisodesNotifier {
  late PodcastRepository _repository;

  @override
  PodcastEpisodesState build(int subscriptionId) {
    _repository = ref.read(podcastRepositoryProvider);
    return const PodcastEpisodesState();
  }

  Future<void> loadEpisodes({
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

  Future<void> loadMoreEpisodes() async {
    if (state.isLoadingMore || !state.hasMore) return;

    state = state.copyWith(isLoadingMore: true);

    try {
      final response = await _repository.listEpisodes(
        subscriptionId: subscriptionId,
        page: state.nextPage ?? 1,
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

  Future<void> refresh() async {
    state = state.copyWith(episodes: []);
    await loadEpisodes();
  }
}

// Note: Models are defined in separate files. This file only contains providers.