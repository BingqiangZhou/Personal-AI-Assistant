import 'package:equatable/equatable.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:just_audio/just_audio.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../../../../core/network/dio_client.dart';
import '../../../../core/providers/core_providers.dart';
import '../../data/models/podcast_episode_model.dart';
import '../../data/models/podcast_playback_model.dart';
import '../../data/models/podcast_subscription_model.dart';
import '../../data/repositories/podcast_repository.dart';
import '../../data/services/podcast_api_service.dart';

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

// === Audio Player Provider ===

@riverpod
class AudioPlayerNotifier extends _$AudioPlayerNotifier {
  late final AudioPlayer _player;
  late PodcastRepository _repository;

  @override
  AudioPlayerState build() {
    _player = AudioPlayer();
    _repository = ref.read(podcastRepositoryProvider);

    // Listen to player state changes
    _player.playerStateStream.listen((playerState) {
      state = state.copyWith(
        isPlaying: playerState.playing,
        processingState: playerState.processingState,
      );

      // Update playback position periodically
      if (playerState.playing) {
        _updatePlaybackPosition();
      }
    });

    // Listen to position changes
    _player.positionStream.listen((position) {
      state = state.copyWith(
        position: position.inMilliseconds,
      );
    });

    // Listen to duration changes
    _player.durationStream.listen((duration) {
      if (duration != null) {
        state = state.copyWith(
          duration: duration.inMilliseconds,
        );
      }
    });

    // Clean up when provider is disposed
    ref.onDispose(() {
      _player.dispose();
    });

    return const AudioPlayerState();
  }

  Future<void> playEpisode(PodcastEpisodeModel episode) async {
    try {
      // Set current episode
      state = state.copyWith(
        currentEpisode: episode,
        isLoading: true,
      );

      // Load and play audio
      await _player.setUrl(episode.audioUrl);
      await _player.play();

      // Update playback state on server
      await _updatePlaybackStateOnServer();

      state = state.copyWith(
        isPlaying: true,
        isLoading: false,
        position: episode.playbackPosition ?? 0,
      );
    } catch (error) {
      state = state.copyWith(
        isLoading: false,
        error: error.toString(),
      );
    }
  }

  Future<void> pause() async {
    try {
      await _player.pause();
      await _updatePlaybackStateOnServer();
    } catch (error) {
      state = state.copyWith(error: error.toString());
    }
  }

  Future<void> resume() async {
    try {
      await _player.play();
      await _updatePlaybackStateOnServer();
    } catch (error) {
      state = state.copyWith(error: error.toString());
    }
  }

  Future<void> seekTo(int position) async {
    try {
      await _player.seek(Duration(milliseconds: position));
      await _updatePlaybackStateOnServer();
    } catch (error) {
      state = state.copyWith(error: error.toString());
    }
  }

  Future<void> setPlaybackRate(double rate) async {
    try {
      await _player.setSpeed(rate);
      await _updatePlaybackStateOnServer();
    } catch (error) {
      state = state.copyWith(error: error.toString());
    }
  }

  Future<void> stop() async {
    try {
      await _player.stop();
      state = state.copyWith(
        currentEpisode: null,
        isPlaying: false,
        position: 0,
      );
    } catch (error) {
      state = state.copyWith(error: error.toString());
    }
  }

  void setExpanded(bool expanded) {
    state = state.copyWith(isExpanded: expanded);
  }

  void _updatePlaybackPosition() {
    if (!state.isPlaying) return;

    Future.delayed(const Duration(seconds: 1), () {
      if (state.isPlaying) {
        _updatePlaybackPosition();
      }
    });
  }

  Future<void> _updatePlaybackStateOnServer() async {
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
      // Log error but don't interrupt playback
      print('Failed to update playback state: $error');
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