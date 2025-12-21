import 'dart:async';

import 'package:audioplayers/audioplayers.dart';
import 'package:equatable/equatable.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../../../../core/providers/core_providers.dart';
import '../../data/models/podcast_episode_model.dart';
import '../../data/models/podcast_playback_model.dart';
import '../../data/models/podcast_subscription_model.dart';
import '../../data/repositories/podcast_repository.dart';
import '../../data/services/podcast_api_service.dart';

part 'podcast_providers_old.g.dart';

enum ProcessingState {
  idle,
  loading,
  buffering,
  ready,
  completed,
}

// === API Service & Repository Providers ===

final podcastApiServiceProvider = Provider<PodcastApiService>((ref) {
  final dio = ref.watch(dioClientProvider).dio;
  return PodcastApiService(dio);
});

final podcastRepositoryProvider = Provider<PodcastRepository>((ref) {
  final apiService = ref.watch(podcastApiServiceProvider);
  return PodcastRepository(apiService);
});

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

  Future<ReparseResponse> reparseSubscription(int subscriptionId, bool forceAll) async {
    try {
      final result = await _repository.reparseSubscription(subscriptionId, forceAll);

      // Refresh the list after re-parsing
      await loadSubscriptions();

      return result;
    } catch (error) {
      rethrow;
    }
  }
}

// === Episode Providers ===

@riverpod
class PodcastEpisodeNotifier extends _$PodcastEpisodeNotifier {
  late PodcastRepository _repository;

  @override
  AsyncValue<PodcastEpisodeListResponse> build() {
    _repository = ref.read(podcastRepositoryProvider);
    return const AsyncValue.loading();
  }

  Future<void> loadEpisodes({
    int? subscriptionId,
    int page = 1,
    int size = 20,
    bool? hasSummary,
    bool? isPlayed,
  }) async {
    state = const AsyncValue.loading();

    try {
      final response = await _repository.listEpisodes(
        subscriptionId: subscriptionId,
        page: page,
        size: size,
        hasSummary: hasSummary,
        isPlayed: isPlayed,
      );
      state = AsyncValue.data(response);
    } catch (error, stackTrace) {
      state = AsyncValue.error(error, stackTrace);
    }
  }

  Future<void> loadMoreEpisodes() async {
    final currentPage = state.value?.page ?? 1;
    final totalPages = state.value?.pages ?? 1;

    if (currentPage >= totalPages) return;

    try {
      final currentData = state.value;
      final response = await _repository.listEpisodes(
        subscriptionId: currentData?.subscriptionId,
        page: currentPage + 1,
        size: currentData?.size ?? 20,
        hasSummary: null,
        isPlayed: null,
      );

      // Combine current and new episodes
      final allEpisodes = [...?currentData?.episodes, ...response.episodes];
      final updatedResponse = PodcastEpisodeListResponse(
        episodes: allEpisodes,
        total: response.total,
        page: response.page,
        size: response.size,
        pages: response.pages,
        subscriptionId: response.subscriptionId,
      );

      state = AsyncValue.data(updatedResponse);
    } catch (error, stackTrace) {
      state = AsyncValue.error(error, stackTrace);
    }
  }
}

final episodeDetailProvider = FutureProvider.family<PodcastEpisodeDetailResponse?, int>((ref, episodeId) async {
  final repository = ref.read(podcastRepositoryProvider);
  return await repository.getEpisode(episodeId);
});

// === Podcast Feed Providers ===

class PodcastFeedState extends Equatable {
  final List<PodcastEpisodeModel> episodes;
  final bool hasMore;
  final int? nextPage;
  final int total;
  final bool isLoading;
  final bool isLoadingMore;
  final String? error;

  const PodcastFeedState({
    this.episodes = const [],
    this.hasMore = true,
    this.nextPage,
    this.total = 0,
    this.isLoading = false,
    this.isLoadingMore = false,
    this.error,
  });

  PodcastFeedState copyWith({
    List<PodcastEpisodeModel>? episodes,
    bool? hasMore,
    int? nextPage,
    int? total,
    bool? isLoading,
    bool? isLoadingMore,
    String? error,
  }) {
    return PodcastFeedState(
      episodes: episodes ?? this.episodes,
      hasMore: hasMore ?? this.hasMore,
      nextPage: nextPage ?? this.nextPage,
      total: total ?? this.total,
      isLoading: isLoading ?? this.isLoading,
      isLoadingMore: isLoadingMore ?? this.isLoadingMore,
      error: error ?? this.error,
    );
  }

  @override
  List<Object?> get props => [
        episodes,
        hasMore,
        nextPage,
        total,
        isLoading,
        isLoadingMore,
        error,
      ];
}

@riverpod
class PodcastFeedNotifier extends _$PodcastFeedNotifier {
  late PodcastRepository _repository;
  static const int _pageSize = 10;

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
        pageSize: _pageSize,
      );

      state = state.copyWith(
        episodes: response.items,
        hasMore: response.hasMore,
        nextPage: response.nextPage,
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

  Future<void> loadMoreFeed() async {
    if (!state.hasMore || state.isLoadingMore || state.nextPage == null) {
      debugPrint('🚫 懒加载被阻止: hasMore=${state.hasMore}, isLoadingMore=${state.isLoadingMore}, nextPage=${state.nextPage}');
      return;
    }

    debugPrint('⏳ 开始加载更多内容，页码: ${state.nextPage}');
    state = state.copyWith(isLoadingMore: true);

    try {
      final response = await _repository.getPodcastFeed(
        page: state.nextPage!,
        pageSize: _pageSize,
      );

      debugPrint('✅ 成功加载 ${response.items.length} 条新内容，总数量: ${response.total}, 还有更多: ${response.hasMore}');
      final allEpisodes = [...state.episodes, ...response.items];

      state = state.copyWith(
        episodes: allEpisodes,
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

// === Audio Player Provider ===

@riverpod
class AudioPlayerNotifier extends _$AudioPlayerNotifier {
  Player? _player;
  late PodcastRepository _repository;
  bool _isDisposed = false;

  @override
  AudioPlayerState build() {
    _repository = ref.read(podcastRepositoryProvider);
    _isDisposed = false;

    // Initialize media kit player
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
      // Initialize MediaKit for audio
      MediaKit.ensureInitialized();

      _player = Player();

      // Listen to player state changes
      _player!.stream.playlist.listen((playlist) {
        if (_isDisposed || !ref.mounted) return;

        if (kDebugMode) {
          debugPrint('🎵 Player state changed: ${_player!.state.playing}, completed: ${_player!.state.completed}, buffering: ${_player!.state.buffering}');
        }

        ProcessingState processingState;
        if (_player!.state.buffering) {
          processingState = ProcessingState.buffering;
        } else if (_player!.state.completed) {
          processingState = ProcessingState.completed;
        } else if (_player!.state.playing) {
          processingState = ProcessingState.ready;
        } else {
          processingState = ProcessingState.idle;
        }

        state = state.copyWith(
          isPlaying: _player!.state.playing,
          isLoading: _player!.state.buffering,
          processingState: processingState,
        );
      });

      // Listen to position changes
      _player!.stream.position.listen((position) {
        if (_isDisposed || !ref.mounted) return;

        if (kDebugMode) {
          debugPrint('🎵 Position updated: ${position.inMilliseconds}ms');
        }

        this.state = this.state.copyWith(
          position: position.inMilliseconds,
        );
      });

      // Listen to duration changes
      _player!.stream.duration.listen((duration) {
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
        debugPrint('🎵 MediaKit player initialized successfully');
      }
    } catch (error) {
      debugPrint('Failed to initialize media kit player: $error');
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
        await _player!.open(Media(episode.audioUrl));
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
        await _player!.play();
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
      await _player!.play();
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
      await _player!.setRate(rate);
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

  // Removed _updatePlaybackPosition - replaced with Timer-based approach

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
      // Log error but don't interrupt playback or crash
      debugPrint('⚠️ Failed to update playback state on server: $error');
      // Don't update the UI state for server errors - continue playback
    }
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

final podcastStatsProvider = FutureProvider<PodcastStatsResponse?>((ref) async {
  final repository = ref.read(podcastRepositoryProvider);
  try {
    return await repository.getStats();
  } catch (error) {
    return null;
  }
});

// === Summary Provider ===

@riverpod
class PodcastSummaryNotifier extends _$PodcastSummaryNotifier {
  late PodcastRepository _repository;

  @override
  AsyncValue<PodcastSummaryResponse?> build(int episodeId) {
    _repository = ref.read(podcastRepositoryProvider);
    return const AsyncValue.data(null);
  }

  Future<PodcastSummaryResponse> generateSummary({
    bool forceRegenerate = false,
    bool? useTranscript,
  }) async {
    state = const AsyncValue.loading();

    try {
      final summary = await _repository.generateSummary(
        episodeId: episodeId,
        forceRegenerate: forceRegenerate,
        useTranscript: useTranscript,
      );
      state = AsyncValue.data(summary);
      return summary;
    } catch (error, stackTrace) {
      state = AsyncValue.error(error, stackTrace);
      rethrow;
    }
  }
}

// === Audio Player State Model ===

class AudioPlayerState extends Equatable {
  final PodcastEpisodeModel? currentEpisode;
  final bool isPlaying;
  final bool isLoading;
  final bool isExpanded;
  final int position;
  final int duration;
  final double playbackRate;
  final ProcessingState? processingState;
  final String? error;

  const AudioPlayerState({
    this.currentEpisode,
    this.isPlaying = false,
    this.isLoading = false,
    this.isExpanded = false,
    this.position = 0,
    this.duration = 0,
    this.playbackRate = 1.0,
    this.processingState,
    this.error,
  });

  AudioPlayerState copyWith({
    PodcastEpisodeModel? currentEpisode,
    bool? isPlaying,
    bool? isLoading,
    bool? isExpanded,
    int? position,
    int? duration,
    double? playbackRate,
    ProcessingState? processingState,
    String? error,
  }) {
    return AudioPlayerState(
      currentEpisode: currentEpisode ?? this.currentEpisode,
      isPlaying: isPlaying ?? this.isPlaying,
      isLoading: isLoading ?? this.isLoading,
      isExpanded: isExpanded ?? this.isExpanded,
      position: position ?? this.position,
      duration: duration ?? this.duration,
      playbackRate: playbackRate ?? this.playbackRate,
      processingState: processingState ?? this.processingState,
      error: error ?? this.error,
    );
  }

  double get progress {
    if (duration == 0) return 0.0;
    return (position / duration).clamp(0.0, 1.0);
  }

  String get formattedPosition {
    final duration = Duration(milliseconds: position);
    final minutes = duration.inMinutes.remainder(60);
    final seconds = duration.inSeconds.remainder(60);
    return '${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';
  }

  String get formattedDuration {
    final duration = Duration(milliseconds: this.duration);
    final hours = duration.inHours;
    final minutes = duration.inMinutes.remainder(60);
    final seconds = duration.inSeconds.remainder(60);

    if (hours > 0) {
      return '${hours.toString().padLeft(2, '0')}:${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';
    }
    return '${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';
  }

  @override
  List<Object?> get props => [
        currentEpisode,
        isPlaying,
        isLoading,
        isExpanded,
        position,
        duration,
        playbackRate,
        processingState,
        error,
      ];
}