import 'dart:async';

import 'package:audio_service/audio_service.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:riverpod/riverpod.dart';

import '../../../../main.dart' as main_app;
import 'audio_handler.dart';

import '../../../../core/providers/core_providers.dart';
import '../../../../core/network/exceptions/network_exceptions.dart';
import '../../../auth/presentation/providers/auth_provider.dart';
import '../../data/models/podcast_episode_model.dart';
import '../../data/models/podcast_playback_model.dart';
import '../../data/models/podcast_queue_model.dart';
import '../../data/models/podcast_subscription_model.dart';
import '../../data/models/audio_player_state_model.dart';
import '../../data/models/podcast_state_models.dart';
import '../../data/models/profile_stats_model.dart';
import '../../data/models/playback_history_lite_model.dart';
import '../../data/repositories/podcast_repository.dart';
import '../../data/services/podcast_api_service.dart';
import 'playback_progress_policy.dart';
import '../../../../core/utils/app_logger.dart' as logger;

// === API Service & Repository Providers ===

final podcastApiServiceProvider = Provider<PodcastApiService>((ref) {
  final dio = ref.watch(dioClientProvider).dio;
  return PodcastApiService(dio);
});

final podcastRepositoryProvider = Provider<PodcastRepository>((ref) {
  final apiService = ref.watch(podcastApiServiceProvider);
  return PodcastRepository(apiService);
});

final audioPlayerProvider =
    NotifierProvider<AudioPlayerNotifier, AudioPlayerState>(
      AudioPlayerNotifier.new,
    );

String? _extractSubscriptionTitle(Map<String, dynamic>? subscription) {
  if (subscription == null) {
    return null;
  }

  final dynamic title = subscription['title'] ?? subscription['name'];
  if (title is String && title.trim().isNotEmpty) {
    return title;
  }
  return null;
}

@visibleForTesting
PodcastEpisodeModel mergeEpisodeForPlayback(
  PodcastEpisodeModel incoming,
  PodcastEpisodeDetailResponse latest,
) {
  final latestEpisode = latest.toEpisodeModel();
  final backendSubscriptionTitle = _extractSubscriptionTitle(
    latest.subscription,
  );
  final resolvedPlaybackRate = latestEpisode.playbackRate > 0
      ? latestEpisode.playbackRate
      : incoming.playbackRate;

  return latestEpisode.copyWith(
    subscriptionTitle: backendSubscriptionTitle ?? incoming.subscriptionTitle,
    subscriptionImageUrl:
        latestEpisode.subscriptionImageUrl ?? incoming.subscriptionImageUrl,
    description: latestEpisode.description ?? incoming.description,
    imageUrl: latestEpisode.imageUrl ?? incoming.imageUrl,
    itemLink: latestEpisode.itemLink ?? incoming.itemLink,
    transcriptUrl: latestEpisode.transcriptUrl ?? incoming.transcriptUrl,
    transcriptContent:
        latestEpisode.transcriptContent ?? incoming.transcriptContent,
    aiSummary: latestEpisode.aiSummary ?? incoming.aiSummary,
    summaryVersion: latestEpisode.summaryVersion ?? incoming.summaryVersion,
    aiConfidenceScore:
        latestEpisode.aiConfidenceScore ?? incoming.aiConfidenceScore,
    metadata: latestEpisode.metadata ?? incoming.metadata,
    playCount: latestEpisode.playCount > 0
        ? latestEpisode.playCount
        : incoming.playCount,
    lastPlayedAt: latestEpisode.lastPlayedAt ?? incoming.lastPlayedAt,
    playbackPosition:
        latestEpisode.playbackPosition ?? incoming.playbackPosition,
    audioDuration: latestEpisode.audioDuration ?? incoming.audioDuration,
    audioFileSize: latestEpisode.audioFileSize ?? incoming.audioFileSize,
    audioUrl: latestEpisode.audioUrl.isNotEmpty
        ? latestEpisode.audioUrl
        : incoming.audioUrl,
    playbackRate: resolvedPlaybackRate,
    isPlayed: latestEpisode.isPlayed || incoming.isPlayed,
  );
}

@visibleForTesting
Future<PodcastEpisodeModel> resolveEpisodeForPlayback(
  PodcastEpisodeModel incoming,
  Future<PodcastEpisodeDetailResponse> Function() fetchLatest,
) async {
  try {
    final latest = await fetchLatest();
    return mergeEpisodeForPlayback(incoming, latest);
  } catch (_) {
    return incoming;
  }
}

class AudioPlayerNotifier extends Notifier<AudioPlayerState> {
  late PodcastRepository _repository;
  bool _isDisposed = false;
  bool _isPlayingEpisode = false;
  bool _isRestoringLastPlayed = false;
  StreamSubscription? _playerStateSubscription;
  StreamSubscription? _positionSubscription;
  StreamSubscription? _durationSubscription;
  bool? _lastPlayingState; // Track last playing state to reduce log spam
  ProcessingState? _lastProcessingState;
  bool _isHandlingQueueCompletion = false;
  Timer? _syncThrottleTimer;
  Timer? _sleepTimerTickTimer;
  DateTime? _lastPlaybackSyncAt;
  static const Duration _syncInterval = Duration(seconds: 2);

  PodcastAudioHandler get _audioHandler => main_app.audioHandler;

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
      _syncThrottleTimer?.cancel();
      _sleepTimerTickTimer?.cancel();
    });

    return const AudioPlayerState();
  }

  void _setupListeners() {
    if (_isDisposed) return;

    _playerStateSubscription = _audioHandler.playbackState.listen((
      playbackState,
    ) {
      if (_isDisposed || !ref.mounted) return;

      final processingState = _mapProcessingState(
        playbackState.processingState,
      );
      final completedJustNow =
          _lastProcessingState != ProcessingState.completed &&
          processingState == ProcessingState.completed;
      _lastProcessingState = processingState;

      // Only log when state actually changes
      if (kDebugMode && _lastPlayingState != playbackState.playing) {
        logger.AppLogger.debug(
          '[Playback] Playback state changed: ${_lastPlayingState == null
              ? "initial"
              : _lastPlayingState!
              ? "playing"
              : "paused"} -> ${playbackState.playing ? "playing" : "paused"}',
        );
        _lastPlayingState = playbackState.playing;
      }

      // Always update state regardless of _isPlayingEpisode
      // This ensures UI stays in sync with actual playback state
      state = state.copyWith(
        isPlaying: playbackState.playing,
        isLoading: false,
        processingState: processingState,
      );

      if (completedJustNow) {
        unawaited(_handleTrackCompleted());
      }
    });

    // CRITICAL: Use _audioHandler.positionStream instead of AudioService.position
    // AudioService is NOT available on desktop platforms (Windows, macOS, Linux)
    // _audioHandler.positionStream works on both mobile and desktop
    _positionSubscription = _audioHandler.positionStream.listen((position) {
      if (_isDisposed || !ref.mounted) return;

      state = state.copyWith(position: position.inMilliseconds);
      if (state.isPlaying) {
        unawaited(_updatePlaybackStateOnServer());
      }
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
        final shouldUpdate =
            currentDuration == 0 ||
            (newDuration > 0 &&
                (newDuration - currentDuration).abs() > currentDuration * 0.05);

        if (shouldUpdate && newDuration != currentDuration) {
          if (kDebugMode) {
            logger.AppLogger.debug(
              '[DURATION UPDATE] ${currentDuration}ms -> ${newDuration}ms (from audio stream)',
            );
          }
          state = state.copyWith(duration: newDuration);
        }
      }
    });

    if (kDebugMode) {
      logger.AppLogger.debug('[OK] Audio listeners set up successfully');
    }
  }

  ProcessingState _mapProcessingState(AudioProcessingState state) {
    switch (state) {
      case AudioProcessingState.idle:
        return ProcessingState.idle;
      case AudioProcessingState.loading:
        return ProcessingState.loading;
      case AudioProcessingState.buffering:
        return ProcessingState.buffering;
      case AudioProcessingState.ready:
        return ProcessingState.ready;
      case AudioProcessingState.completed:
        return ProcessingState.completed;
      default:
        return ProcessingState.idle;
    }
  }

  Future<void> _handleTrackCompleted() async {
    if (_isDisposed || !ref.mounted) {
      return;
    }

    state = state.copyWith(isPlaying: false, position: 0);
    await _updatePlaybackStateOnServer(immediate: true);

    // If sleep timer is set to "after episode", stop here
    if (state.sleepTimerAfterEpisode) {
      logger.AppLogger.debug(
        '[Sleep Timer] Sleep timer: stop after episode triggered',
      );
      cancelSleepTimer();
      return;
    }

    if (state.playSource != PlaySource.queue || _isHandlingQueueCompletion) {
      return;
    }

    _isHandlingQueueCompletion = true;
    try {
      final queue = await ref
          .read(podcastQueueControllerProvider.notifier)
          .onQueueTrackCompleted();

      final next = queue.currentItem;
      if (next == null) {
        state = state.copyWith(
          isPlaying: false,
          position: 0,
          playSource: PlaySource.direct,
          clearCurrentQueueEpisodeId: true,
        );
        return;
      }

      await playEpisode(
        next.toEpisodeModel(),
        source: PlaySource.queue,
        queueEpisodeId: next.episodeId,
      );
    } catch (error) {
      logger.AppLogger.debug(
        '[Error] Failed to advance queue on completion: $error',
      );
    } finally {
      _isHandlingQueueCompletion = false;
    }
  }

  void syncQueueState(PodcastQueueModel queue) {
    if (_isDisposed || !ref.mounted) {
      return;
    }
    state = state.copyWith(
      queue: queue,
      currentQueueEpisodeId:
          queue.currentEpisodeId ?? state.currentQueueEpisodeId,
    );
  }

  void setQueueSyncing(bool syncing) {
    if (_isDisposed || !ref.mounted) {
      return;
    }
    state = state.copyWith(queueSyncing: syncing);
  }

  Future<void> restoreLastPlayedEpisodeIfNeeded() async {
    if (_isDisposed || !ref.mounted) {
      return;
    }
    if (_isRestoringLastPlayed) {
      logger.AppLogger.debug(
        '[PlaybackRestore] Skip restore: restoration already in progress',
      );
      return;
    }
    if (_isPlayingEpisode || state.currentEpisode != null) {
      logger.AppLogger.debug(
        '[PlaybackRestore] Skip restore: player already has active state',
      );
      return;
    }
    if (!ref.read(authProvider).isAuthenticated) {
      logger.AppLogger.debug(
        '[PlaybackRestore] Skip restore: user is not authenticated',
      );
      return;
    }

    _isRestoringLastPlayed = true;
    try {
      logger.AppLogger.debug(
        '[PlaybackRestore] Restoring last played episode for mini player',
      );

      final response = await _repository.getPlaybackHistory(page: 1, size: 20);
      if (_isDisposed || !ref.mounted) {
        return;
      }
      if (_isPlayingEpisode || state.currentEpisode != null) {
        logger.AppLogger.debug(
          '[PlaybackRestore] Skip apply: player state changed while restoring',
        );
        return;
      }
      if (response.episodes.isEmpty) {
        logger.AppLogger.debug(
          '[PlaybackRestore] Skip restore: no playback history found',
        );
        return;
      }

      final episodes = [...response.episodes]
        ..sort((a, b) {
          final aTime =
              a.lastPlayedAt ?? DateTime.fromMillisecondsSinceEpoch(0);
          final bTime =
              b.lastPlayedAt ?? DateTime.fromMillisecondsSinceEpoch(0);
          return bTime.compareTo(aTime);
        });
      final latest = episodes.first;
      final resolvedPlaybackRate = latest.playbackRate > 0
          ? latest.playbackRate
          : 1.0;
      final resumePositionMs = normalizeResumePositionMs(
        latest.playbackPosition,
        latest.audioDuration,
      );
      final durationMs = (latest.audioDuration ?? 0) * 1000;

      logger.AppLogger.debug(
        '[PlaybackRestore] Candidate episode=${latest.id}, position=${resumePositionMs}ms',
      );

      try {
        await _audioHandler.setEpisode(
          id: latest.id.toString(),
          url: latest.audioUrl,
          title: latest.title,
          artist: latest.subscriptionTitle ?? 'Unknown Podcast',
          artUri: latest.imageUrl ?? latest.subscriptionImageUrl,
          autoPlay: false,
        );
        if (resumePositionMs > 0) {
          await _audioHandler.seek(Duration(milliseconds: resumePositionMs));
        }
        await _audioHandler.setSpeed(resolvedPlaybackRate);
      } catch (error) {
        logger.AppLogger.debug(
          '[PlaybackRestore] Failed to preload restored episode: $error',
        );
      }

      if (_isDisposed || !ref.mounted) {
        return;
      }
      if (_isPlayingEpisode || state.currentEpisode != null) {
        logger.AppLogger.debug(
          '[PlaybackRestore] Skip apply: player state changed after preloading',
        );
        return;
      }

      state = state.copyWith(
        currentEpisode: latest.copyWith(
          playbackRate: resolvedPlaybackRate,
          playbackPosition: (resumePositionMs / 1000).round(),
        ),
        isPlaying: false,
        isLoading: false,
        isExpanded: false,
        position: resumePositionMs,
        duration: durationMs,
        playbackRate: resolvedPlaybackRate,
        error: null,
      );

      logger.AppLogger.debug(
        '[PlaybackRestore] Restored episode ${latest.id} to ${state.formattedPosition}',
      );
    } catch (error) {
      logger.AppLogger.debug(
        '[PlaybackRestore] Failed to restore last played episode: $error',
      );
    } finally {
      _isRestoringLastPlayed = false;
    }
  }

  Future<PodcastEpisodeModel> _resolveEpisodeForPlayback(
    PodcastEpisodeModel episode,
  ) async {
    if (_isDisposed || !ref.mounted) {
      return episode;
    }

    logger.AppLogger.debug(
      '[PlaybackRestore] Fetch latest playback state before play: episode=${episode.id}',
    );
    final resolved = await resolveEpisodeForPlayback(episode, () async {
      return _repository.getEpisode(episode.id);
    });

    if (identical(resolved, episode)) {
      logger.AppLogger.debug(
        '[PlaybackRestore] Fallback to local episode data: episode=${episode.id}',
      );
    } else {
      logger.AppLogger.debug(
        '[PlaybackRestore] Using server playback state: episode=${resolved.id}, position=${resolved.playbackPosition ?? 0}s',
      );
    }

    return resolved;
  }

  Future<void> playEpisode(
    PodcastEpisodeModel episode, {
    PlaySource source = PlaySource.direct,
    int? queueEpisodeId,
  }) async {
    if (_isPlayingEpisode) {
      logger.AppLogger.debug(
        '[Playback] playEpisode already in progress, ignoring duplicate call',
      );
      return;
    }

    final isSameEpisode = state.currentEpisode?.id == episode.id;
    final isCompleted = state.processingState == ProcessingState.completed;
    if (isSameEpisode && !isCompleted) {
      if (state.isPlaying) {
        logger.AppLogger.debug(
          '[Warn] Same episode already playing, skip reloading source',
        );
        return;
      }
      logger.AppLogger.debug(
        '[Playback] Same episode paused, fast resume without reloading source',
      );
      await resume();
      return;
    }

    _isPlayingEpisode = true;
    var episodeForPlayback = episode;

    try {
      episodeForPlayback = await _resolveEpisodeForPlayback(episode);
      if (!ref.mounted || _isDisposed) {
        _isPlayingEpisode = false;
        return;
      }

      var effectiveSource = source;
      var effectiveQueueEpisodeId = queueEpisodeId;

      if (source == PlaySource.direct) {
        final preparedQueue = await _prepareManualPlayQueue(
          episodeForPlayback.id,
        );
        if (preparedQueue != null) {
          effectiveSource = PlaySource.queue;
          effectiveQueueEpisodeId = episodeForPlayback.id;
        }
      }
      logger.AppLogger.debug('[Playback] ===== playEpisode called =====');
      logger.AppLogger.debug('[Playback] Episode ID: ${episodeForPlayback.id}');
      logger.AppLogger.debug(
        '[Playback] Episode Title: ${episodeForPlayback.title}',
      );
      logger.AppLogger.debug(
        '[Playback] Audio URL: ${episodeForPlayback.audioUrl}',
      );
      logger.AppLogger.debug(
        '[Playback] Subscription ID: ${episodeForPlayback.subscriptionId}',
      );

      if (!ref.mounted || _isDisposed) {
        _isPlayingEpisode = false;
        return;
      }

      final queueSnapshot = state.queue;
      final queueSyncing = state.queueSyncing;
      var targetPlaybackRate = state.playbackRate;

      try {
        final effectiveRate = await _repository.getEffectivePlaybackRate(
          subscriptionId: episodeForPlayback.subscriptionId,
        );
        targetPlaybackRate = effectiveRate.effectivePlaybackRate;
      } catch (error) {
        logger.AppLogger.debug(
          'Failed to resolve effective playback rate, using current state value: $error',
        );
      }

      // ===== STEP 1: Pause current playback instead of stop =====
      // Using pause() instead of stop() to avoid clearing the audio source
      // This maintains the media session state better
      logger.AppLogger.debug('[Playback] Step 1: Pausing current playback');
      try {
        await _audioHandler.pause();
        logger.AppLogger.debug('[OK] Paused');
      } catch (e) {
        logger.AppLogger.debug('[Error] Pause error (ignorable): $e');
      }

      state = const AudioPlayerState().copyWith(
        playbackRate: targetPlaybackRate,
        queue: queueSnapshot,
        queueSyncing: queueSyncing,
        playSource: effectiveSource,
        currentQueueEpisodeId: effectiveSource == PlaySource.queue
            ? (effectiveQueueEpisodeId ?? episodeForPlayback.id)
            : null,
      );

      if (!ref.mounted || _isDisposed) return;

      // ===== STEP 2: Set new episode info with duration from backend =====
      logger.AppLogger.debug('[Playback] Step 2: Setting new episode info');
      // CRITICAL: Backend audioDuration is in SECONDS, convert to MILLISECONDS
      final durationMs = (episodeForPlayback.audioDuration ?? 0) * 1000;
      final resumePositionMs = normalizeResumePositionMs(
        episodeForPlayback.playbackPosition,
        episodeForPlayback.audioDuration,
      );
      logger.AppLogger.debug(
        '[Playback] Using backend duration: ${episodeForPlayback.audioDuration}s = ${durationMs}ms',
      );
      state = state.copyWith(
        currentEpisode: episodeForPlayback,
        isLoading: true,
        isPlaying: false, // Keep false until actually playing
        duration: durationMs, // Convert seconds to milliseconds
        error: null,
      );

      // ===== STEP 3: Set new episode with metadata =====
      // CRITICAL: Use setEpisode() to properly set MediaItem, validate artUri, and load audio
      // artUri validation is built into setEpisode() - only http/https URLs are accepted
      logger.AppLogger.debug(
        '[Playback] Step 3: Setting new episode with metadata',
      );
      logger.AppLogger.debug(
        '[Playback] Backend duration already set: ${state.duration}ms',
      );
      logger.AppLogger.debug(
        '[Playback] Image URL: ${episodeForPlayback.imageUrl ?? "NULL"}',
      );

      try {
        await _audioHandler.setEpisode(
          id: episodeForPlayback.id.toString(),
          url: episodeForPlayback.audioUrl,
          title: episodeForPlayback.title,
          artist: episodeForPlayback.subscriptionTitle ?? 'Unknown Podcast',
          artUri:
              episodeForPlayback.imageUrl ??
              episodeForPlayback.subscriptionImageUrl,
          autoPlay:
              false, // We'll manually start playback after restoring position/speed
        );
        logger.AppLogger.debug('[OK] Episode loaded successfully');
      } catch (loadError) {
        logger.AppLogger.debug('[Error] Failed to load episode: $loadError');
        throw Exception('Failed to load audio: $loadError');
      }

      if (!ref.mounted || _isDisposed) return;

      // ===== STEP 4: Restore playback position =====
      if (resumePositionMs > 0) {
        logger.AppLogger.debug(
          '[Playback] Step 4: Seeking to saved position: ${resumePositionMs}ms',
        );
        try {
          await _audioHandler.seek(Duration(milliseconds: resumePositionMs));
          logger.AppLogger.debug('[OK] Seek completed');
        } catch (e) {
          logger.AppLogger.debug('[Error] Seek error: $e');
        }
      }

      if (!ref.mounted || _isDisposed) return;

      // ===== STEP 5: Restore playback rate =====
      logger.AppLogger.debug(
        'Step 5: Applying effective playback rate ${targetPlaybackRate}x',
      );
      try {
        await _audioHandler.setSpeed(targetPlaybackRate);
      } catch (e) {
        logger.AppLogger.debug('Failed to apply playback rate: $e');
      }

      // ===== STEP 6: Start playback =====
      logger.AppLogger.debug('[Playback] Step 6: Starting playback');
      try {
        await _audioHandler.play();
        logger.AppLogger.debug('[OK] Playback started');

        if (ref.mounted && !_isDisposed) {
          state = state.copyWith(
            isPlaying: true,
            isLoading: false,
            position: resumePositionMs,
            playbackRate: targetPlaybackRate,
          );
        }
      } catch (playError) {
        logger.AppLogger.debug('[Error] Failed to start playback: $playError');
        _isPlayingEpisode = false;
        throw Exception('Failed to start playback: $playError');
      }

      logger.AppLogger.debug('[Playback] ===== playEpisode completed =====');

      // Update playback state on server (non-blocking)
      if (ref.mounted && !_isDisposed) {
        _updatePlaybackStateOnServer().catchError((error) {
          logger.AppLogger.debug('[Error] Server update failed: $error');
        });
      }

      // Release the lock
      _isPlayingEpisode = false;
    } catch (error) {
      logger.AppLogger.debug('[Error] ===== Failed to play episode =====');
      logger.AppLogger.debug('[Playback] Episode ID: ${episodeForPlayback.id}');
      logger.AppLogger.debug(
        '[Playback] Audio URL: ${episodeForPlayback.audioUrl}',
      );
      logger.AppLogger.debug('[Error] Error: $error');

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

  Future<PodcastQueueModel?> _prepareManualPlayQueue(int episodeId) async {
    if (_isDisposed || !ref.mounted) {
      return null;
    }

    try {
      final queueController = ref.read(podcastQueueControllerProvider.notifier);
      var queue = await queueController.addToQueue(episodeId);
      final orderedEpisodeIds = <int>[
        episodeId,
        ...queue.items
            .map((item) => item.episodeId)
            .where((id) => id != episodeId),
      ];
      final currentOrder = queue.items.map((item) => item.episodeId).toList();

      if (!listEquals(currentOrder, orderedEpisodeIds)) {
        queue = await queueController.reorderQueue(orderedEpisodeIds);
      }

      if (queue.currentEpisodeId != episodeId) {
        queue = await queueController.setCurrentEpisode(episodeId);
      }

      return queue;
    } catch (error) {
      logger.AppLogger.debug('Failed to prepare manual play queue: $error');
      return null;
    }
  }

  Future<void> pause() async {
    if (_isDisposed) return;

    try {
      logger.AppLogger.debug(
        '[Playback] pause() called, current isPlaying: ${state.isPlaying}',
      );

      // IMPORTANT: Don't manually update state here - let the playbackState listener handle it
      // The listener will update the state when playbackState.playing changes
      // This avoids race conditions where manual state gets overwritten

      await _audioHandler.pause();
      logger.AppLogger.debug(
        '[Playback] AudioHandler.pause() completed, waiting for playbackState listener to update UI',
      );

      if (ref.mounted && !_isDisposed) {
        await _updatePlaybackStateOnServer(immediate: true);
      }
    } catch (error) {
      logger.AppLogger.debug('[Error] pause() error: $error');
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(error: error.toString());
      }
    }
  }

  Future<void> resume() async {
    if (_isDisposed) return;

    try {
      logger.AppLogger.debug(
        '[Playback] resume() called, current isPlaying: ${state.isPlaying}',
      );

      // IMPORTANT: Don't manually update state here - let the playbackState listener handle it
      // The listener will update the state when playbackState.playing changes
      // This avoids race conditions where manual state gets overwritten

      await _audioHandler.play();
      logger.AppLogger.debug(
        '[Playback] AudioHandler.play() completed, waiting for playbackState listener to update UI',
      );

      if (ref.mounted && !_isDisposed) {
        unawaited(
          _updatePlaybackStateOnServer().catchError((error) {
            logger.AppLogger.debug(
              '[Error] Server update failed after resume: $error',
            );
          }),
        );
      }
    } catch (error) {
      logger.AppLogger.debug('[Error] resume() error: $error');
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
        await _updatePlaybackStateOnServer(immediate: true);
      }
    } catch (error) {
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(error: error.toString());
      }
    }
  }

  Future<void> setPlaybackRate(
    double rate, {
    bool applyToSubscription = false,
  }) async {
    if (_isDisposed) return;

    try {
      final currentEpisode = state.currentEpisode;
      if (applyToSubscription && currentEpisode == null) {
        throw StateError(
          'A current episode is required when applying to subscription',
        );
      }

      await _audioHandler.setSpeed(rate);
      final applied = await _repository.applyPlaybackRatePreference(
        playbackRate: rate,
        applyToSubscription: applyToSubscription,
        subscriptionId: currentEpisode?.subscriptionId,
      );

      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(playbackRate: applied.effectivePlaybackRate);
        await _updatePlaybackStateOnServer(immediate: true);
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
      if (ref.mounted && !_isDisposed) {
        await _updatePlaybackStateOnServer(immediate: true);
      }
      await _audioHandler.stop();
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(
          clearCurrentEpisode: true,
          isPlaying: false,
          position: 0,
          playSource: PlaySource.direct,
          clearCurrentQueueEpisodeId: true,
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

  // ===== Sleep Timer =====

  void setSleepTimer(Duration duration) {
    if (_isDisposed || !ref.mounted) return;

    _sleepTimerTickTimer?.cancel();

    final endTime = DateTime.now().add(duration);
    state = state.copyWith(
      sleepTimerEndTime: endTime,
      sleepTimerAfterEpisode: false,
      sleepTimerRemainingLabel: _formatRemainingTime(duration),
    );

    logger.AppLogger.debug(
      '[Sleep Timer] Sleep timer set: ${duration.inMinutes} minutes',
    );

    _sleepTimerTickTimer = Timer.periodic(
      const Duration(seconds: 1),
      (_) => _onSleepTimerTick(),
    );
  }

  void setSleepTimerAfterEpisode() {
    if (_isDisposed || !ref.mounted) return;

    _sleepTimerTickTimer?.cancel();

    state = state.copyWith(
      sleepTimerAfterEpisode: true,
      sleepTimerRemainingLabel: '本集',
      clearSleepTimer: false,
    );
    // Explicitly clear the endTime by using copyWith then overriding
    state = AudioPlayerState(
      currentEpisode: state.currentEpisode,
      queue: state.queue,
      currentQueueEpisodeId: state.currentQueueEpisodeId,
      playSource: state.playSource,
      queueSyncing: state.queueSyncing,
      isPlaying: state.isPlaying,
      isLoading: state.isLoading,
      isExpanded: state.isExpanded,
      position: state.position,
      duration: state.duration,
      playbackRate: state.playbackRate,
      processingState: state.processingState,
      error: state.error,
      sleepTimerEndTime: null,
      sleepTimerAfterEpisode: true,
      sleepTimerRemainingLabel: '本集',
    );

    logger.AppLogger.debug(
      '[Sleep Timer] Sleep timer set: after current episode',
    );
  }

  void cancelSleepTimer() {
    if (_isDisposed || !ref.mounted) return;

    _sleepTimerTickTimer?.cancel();
    _sleepTimerTickTimer = null;

    state = state.copyWith(clearSleepTimer: true);

    logger.AppLogger.debug('[Sleep Timer] Sleep timer cancelled');
  }

  void _onSleepTimerTick() {
    if (_isDisposed || !ref.mounted) return;

    final endTime = state.sleepTimerEndTime;
    if (endTime == null) {
      _sleepTimerTickTimer?.cancel();
      _sleepTimerTickTimer = null;
      return;
    }

    final remaining = endTime.difference(DateTime.now());
    if (remaining.isNegative || remaining.inSeconds <= 0) {
      // Timer expired, pause playback
      logger.AppLogger.debug(
        '[Sleep Timer] Sleep timer expired, pausing playback',
      );
      _sleepTimerTickTimer?.cancel();
      _sleepTimerTickTimer = null;
      state = state.copyWith(clearSleepTimer: true);
      pause();
      return;
    }

    state = state.copyWith(
      sleepTimerRemainingLabel: _formatRemainingTime(remaining),
    );
  }

  String _formatRemainingTime(Duration d) {
    final hours = d.inHours;
    final minutes = d.inMinutes.remainder(60);
    final seconds = d.inSeconds.remainder(60);
    if (hours > 0) {
      return '$hours:${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';
    }
    return '${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';
  }

  Future<void> _updatePlaybackStateOnServer({bool immediate = false}) async {
    if (_isDisposed) return;

    final episode = state.currentEpisode;
    if (episode == null) return;

    // If immediate (pause/seek/stop/completed), send right away
    if (immediate) {
      _syncThrottleTimer?.cancel();
      _syncThrottleTimer = null;
      await _sendPlaybackUpdate(episode);
      _lastPlaybackSyncAt = DateTime.now();
      return;
    }

    await _scheduleThrottledSync(episode);
  }

  Future<void> _scheduleThrottledSync(PodcastEpisodeModel episode) async {
    final now = DateTime.now();
    final lastSync = _lastPlaybackSyncAt;

    if (lastSync == null || now.difference(lastSync) >= _syncInterval) {
      await _sendPlaybackUpdate(episode);
      _lastPlaybackSyncAt = DateTime.now();
      return;
    }

    if (_syncThrottleTimer?.isActive ?? false) {
      return;
    }

    final remaining = _syncInterval - now.difference(lastSync);
    _syncThrottleTimer = Timer(remaining, () {
      if (_isDisposed) return;
      final currentEpisode = state.currentEpisode;
      if (currentEpisode == null) return;

      _sendPlaybackUpdate(currentEpisode).then((_) {
        _lastPlaybackSyncAt = DateTime.now();
      });
    });
  }

  Future<void> _sendPlaybackUpdate(PodcastEpisodeModel episode) async {
    if (_isDisposed) return;

    final payload = buildPersistPayload(
      state.position,
      state.duration,
      state.isPlaying,
    );

    try {
      await _repository.updatePlaybackProgress(
        episodeId: episode.id,
        position: payload.positionSec,
        isPlaying: payload.isPlaying,
        playbackRate: state.playbackRate,
      );
    } catch (error) {
      // Log more detailed error for debugging
      logger.AppLogger.debug(
        '[Error] Failed to update playback state on server: $error',
      );
      logger.AppLogger.debug('[Playback] Episode ID: ${episode.id}');
      logger.AppLogger.debug(
        '[Playback] Position: ${state.position}ms (${(state.position / 1000).round()}s)',
      );
      logger.AppLogger.debug('[Playback] Is Playing: ${state.isPlaying}');
      logger.AppLogger.debug('[Playback] Playback Rate: ${state.playbackRate}');

      // Check if it's an authentication error
      if (error.toString().contains('401') ||
          error.toString().contains('authentication')) {
        logger.AppLogger.debug(
          '[Error] Authentication error - user may need to log in again',
        );
      }

      // Don't update the UI state for server errors - continue playback
    }
  }
}

final podcastQueueControllerProvider =
    AsyncNotifierProvider<PodcastQueueController, PodcastQueueModel>(
      PodcastQueueController.new,
    );

class PodcastQueueController extends AsyncNotifier<PodcastQueueModel> {
  late PodcastRepository _repository;
  Future<PodcastQueueModel>? _inFlightQueueLoad;
  final Map<int, Future<PodcastQueueModel>> _inFlightAddToQueueByEpisodeId =
      <int, Future<PodcastQueueModel>>{};
  DateTime? _lastQueueRefreshAt;
  static const Duration _queueRefreshThrottle = Duration(seconds: 20);

  @override
  FutureOr<PodcastQueueModel> build() async {
    _repository = ref.read(podcastRepositoryProvider);
    try {
      return await _loadQueueInternal(
        forceRefresh: false,
        trackSyncing: false,
        setErrorStateOnFailure: false,
      );
    } catch (_) {
      return PodcastQueueModel.empty();
    }
  }

  bool _hasFreshQueueState() {
    if (_lastQueueRefreshAt == null) {
      return false;
    }
    return DateTime.now().difference(_lastQueueRefreshAt!) <
        _queueRefreshThrottle;
  }

  void _applyQueue(PodcastQueueModel queue) {
    state = AsyncValue.data(queue);
    _lastQueueRefreshAt = DateTime.now();
    ref.read(audioPlayerProvider.notifier).syncQueueState(queue);
  }

  Future<PodcastQueueModel> _loadQueueInternal({
    required bool forceRefresh,
    bool trackSyncing = true,
    bool setErrorStateOnFailure = true,
  }) {
    final inFlight = _inFlightQueueLoad;
    if (inFlight != null) {
      return inFlight;
    }

    final cachedQueue = state.value;
    if (!forceRefresh && cachedQueue != null && _hasFreshQueueState()) {
      return Future.value(cachedQueue);
    }

    if (trackSyncing) {
      ref.read(audioPlayerProvider.notifier).setQueueSyncing(true);
    }

    final loadFuture = () async {
      try {
        final queue = await _repository.getQueue();
        _applyQueue(queue);
        return queue;
      } catch (error, stackTrace) {
        if (setErrorStateOnFailure || state.value == null) {
          state = AsyncValue.error(error, stackTrace);
        }
        rethrow;
      } finally {
        _inFlightQueueLoad = null;
        if (trackSyncing) {
          ref.read(audioPlayerProvider.notifier).setQueueSyncing(false);
        }
      }
    }();

    _inFlightQueueLoad = loadFuture;
    return loadFuture;
  }

  Future<PodcastQueueModel> loadQueue({bool forceRefresh = true}) async {
    return _loadQueueInternal(
      forceRefresh: forceRefresh,
      trackSyncing: true,
      setErrorStateOnFailure: true,
    );
  }

  Future<void> refreshQueueInBackground() async {
    try {
      await _loadQueueInternal(
        forceRefresh: false,
        trackSyncing: false,
        setErrorStateOnFailure: false,
      );
    } catch (_) {
      // Keep existing queue UI state when background refresh fails.
    }
  }

  Future<PodcastQueueModel> addToQueue(int episodeId) async {
    final inFlight = _inFlightAddToQueueByEpisodeId[episodeId];
    if (inFlight != null) {
      return inFlight;
    }

    ref.read(audioPlayerProvider.notifier).setQueueSyncing(true);
    final addFuture = () async {
      try {
        final queue = await _repository.addQueueItem(episodeId);
        _applyQueue(queue);
        return queue;
      } catch (error, stackTrace) {
        state = AsyncValue.error(error, stackTrace);
        rethrow;
      } finally {
        ref.read(audioPlayerProvider.notifier).setQueueSyncing(false);
      }
    }();

    _inFlightAddToQueueByEpisodeId[episodeId] = addFuture;
    try {
      return await addFuture;
    } finally {
      if (identical(_inFlightAddToQueueByEpisodeId[episodeId], addFuture)) {
        _inFlightAddToQueueByEpisodeId.remove(episodeId);
      }
    }
  }

  Future<PodcastQueueModel> removeFromQueue(int episodeId) async {
    ref.read(audioPlayerProvider.notifier).setQueueSyncing(true);
    try {
      final queue = await _repository.removeQueueItem(episodeId);
      _applyQueue(queue);
      return queue;
    } catch (error, stackTrace) {
      state = AsyncValue.error(error, stackTrace);
      rethrow;
    } finally {
      ref.read(audioPlayerProvider.notifier).setQueueSyncing(false);
    }
  }

  Future<PodcastQueueModel> reorderQueue(List<int> episodeIds) async {
    ref.read(audioPlayerProvider.notifier).setQueueSyncing(true);
    try {
      final queue = await _repository.reorderQueueItems(episodeIds);
      _applyQueue(queue);
      return queue;
    } catch (error, stackTrace) {
      state = AsyncValue.error(error, stackTrace);
      rethrow;
    } finally {
      ref.read(audioPlayerProvider.notifier).setQueueSyncing(false);
    }
  }

  Future<PodcastQueueModel> setCurrentEpisode(int episodeId) async {
    ref.read(audioPlayerProvider.notifier).setQueueSyncing(true);
    try {
      final queue = await _repository.setQueueCurrent(episodeId);
      _applyQueue(queue);
      return queue;
    } catch (error, stackTrace) {
      state = AsyncValue.error(error, stackTrace);
      rethrow;
    } finally {
      ref.read(audioPlayerProvider.notifier).setQueueSyncing(false);
    }
  }

  Future<PodcastQueueModel> playFromQueue(int episodeId) async {
    try {
      final queue = await setCurrentEpisode(episodeId);

      final current = queue.currentItem;
      if (current != null) {
        await ref
            .read(audioPlayerProvider.notifier)
            .playEpisode(
              current.toEpisodeModel(),
              source: PlaySource.queue,
              queueEpisodeId: current.episodeId,
            );
      }
      return queue;
    } catch (error, stackTrace) {
      state = AsyncValue.error(error, stackTrace);
      rethrow;
    }
  }

  Future<PodcastQueueModel> onQueueTrackCompleted() async {
    final queue = await _repository.completeQueueCurrent();
    _applyQueue(queue);
    return queue;
  }
}

final podcastSubscriptionProvider =
    NotifierProvider<PodcastSubscriptionNotifier, PodcastSubscriptionState>(
      PodcastSubscriptionNotifier.new,
    );

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
    bool forceRefresh = false,
  }) async {
    // Check if data is fresh and skip refresh if not forced
    if (!forceRefresh && page == 1 && state.isDataFresh()) {
      logger.AppLogger.debug(
        '[Playback] Using cached subscription data (fresh within 5 min)',
      );
      return;
    }

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
        lastRefreshTime: DateTime.now(), // Record refresh time
      );
      logger.AppLogger.debug(
        '[OK] Subscription data loaded at ${DateTime.now()} (total=${response.total}, count=${response.subscriptions.length})',
      );
    } catch (error) {
      state = state.copyWith(isLoading: false, error: error.toString());
      rethrow;
    }
  }

  Future<void> loadMoreSubscriptions({int? categoryId, String? status}) async {
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
        nextPage: (state.nextPage ?? 1) < response.pages
            ? (state.nextPage ?? 1) + 1
            : null,
        currentPage: state.nextPage ?? 1,
        total: response.total,
        isLoadingMore: false,
      );
    } catch (error) {
      state = state.copyWith(isLoadingMore: false, error: error.toString());
    }
  }

  Future<void> refreshSubscriptions({int? categoryId, String? status}) async {
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
        subscribingFeedUrls: state.subscribingFeedUrls
            .where((url) => url != feedUrl)
            .toSet(),
      );

      return subscription;
    } catch (error) {
      // Remove from subscribing set
      state = state.copyWith(
        subscribingFeedUrls: state.subscribingFeedUrls
            .where((url) => url != feedUrl)
            .toSet(),
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
      logger.AppLogger.debug(
        '[Playback] Bulk delete request: subscriptionIds=$subscriptionIds',
      );
      logger.AppLogger.debug(
        '[Playback] Subscription IDs type: ${subscriptionIds.runtimeType}',
      );

      final response = await _repository.bulkDeleteSubscriptions(
        subscriptionIds: subscriptionIds,
      );

      logger.AppLogger.debug(
        '[OK] Bulk delete success: ${response.successCount} deleted, ${response.failedCount} failed',
      );

      // Refresh the list
      await refreshSubscriptions();

      return response;
    } catch (error) {
      logger.AppLogger.debug('[Error] Bulk delete failed: $error');
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

final podcastFeedProvider =
    NotifierProvider<PodcastFeedNotifier, PodcastFeedState>(
      PodcastFeedNotifier.new,
    );

class PodcastFeedNotifier extends Notifier<PodcastFeedState> {
  late PodcastRepository _repository;
  Future<void>? _inFlightInitialLoad;

  @override
  PodcastFeedState build() {
    _repository = ref.read(podcastRepositoryProvider);
    return const PodcastFeedState();
  }

  String _extractReadableErrorMessage(Object error) {
    if (error is AppException) {
      final message = error.message.trim();
      return message.isNotEmpty ? message : 'Network error occurred';
    }

    final message = error.toString().trim();
    return message.isNotEmpty ? message : 'Network error occurred';
  }

  Future<void> loadInitialFeed({
    bool forceRefresh = false,
    bool background = false,
  }) async {
    final currentState = state;
    final hasData = currentState.episodes.isNotEmpty;

    if (!forceRefresh && hasData && currentState.isDataFresh()) {
      return;
    }

    final existingLoad = _inFlightInitialLoad;
    if (existingLoad != null) {
      return existingLoad;
    }

    final shouldShowInitialLoader = !background && !hasData;
    if (shouldShowInitialLoader) {
      state = currentState.copyWith(isLoading: true, clearError: true);
    }

    final loadFuture = () async {
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
          clearError: true,
          lastRefreshTime: DateTime.now(),
        );
      } catch (error) {
        logger.AppLogger.debug('[Error] Failed to load feed: $error');

        // Check if this is an authentication error
        if (error is AuthenticationException) {
          logger.AppLogger.debug(
            'Authentication failed while loading feed, checking auth status.',
          );
          // Trigger auth status check to update state and redirect to login
          ref.read(authProvider.notifier).checkAuthStatus();
        }

        state = state.copyWith(
          isLoading: false,
          error: _extractReadableErrorMessage(error),
        );
      }
    }();

    _inFlightInitialLoad = loadFuture;
    try {
      await loadFuture;
    } finally {
      if (identical(_inFlightInitialLoad, loadFuture)) {
        _inFlightInitialLoad = null;
      }
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
        lastRefreshTime: DateTime.now(),
      );
    } catch (error) {
      logger.AppLogger.debug('[Error] Failed to load more feed: $error');

      // Check if this is an authentication error
      if (error is AuthenticationException) {
        logger.AppLogger.debug(
          'Authentication failed while loading more feed, checking auth status.',
        );
        // Trigger auth status check to update state and redirect to login
        ref.read(authProvider.notifier).checkAuthStatus();
      }

      state = state.copyWith(
        isLoadingMore: false,
        error: _extractReadableErrorMessage(error),
      );
    }
  }

  Future<void> refreshFeed() async {
    await loadInitialFeed(
      forceRefresh: true,
      background: state.episodes.isNotEmpty,
    );
  }

  void clearError() {
    state = state.copyWith(clearError: true);
  }
}

final podcastSearchProvider =
    AsyncNotifierProvider<PodcastSearchNotifier, PodcastEpisodeListResponse>(
      PodcastSearchNotifier.new,
    );

class PodcastSearchNotifier extends AsyncNotifier<PodcastEpisodeListResponse> {
  late PodcastRepository _repository;
  Timer? _debounceTimer;

  @override
  FutureOr<PodcastEpisodeListResponse> build() {
    _repository = ref.read(podcastRepositoryProvider);
    ref.onDispose(() {
      _debounceTimer?.cancel();
    });
    return Future.value(
      const PodcastEpisodeListResponse(
        episodes: [],
        total: 0,
        page: 1,
        size: 20,
        pages: 0,
        subscriptionId: 0,
      ),
    );
  }

  Future<void> searchPodcasts({
    required String query,
    String searchIn = 'all',
    int page = 1,
    int size = 20,
  }) async {
    // Cancel previous debounce timer
    _debounceTimer?.cancel();

    if (query.trim().isEmpty) {
      state = AsyncValue.data(
        const PodcastEpisodeListResponse(
          episodes: [],
          total: 0,
          page: 1,
          size: 20,
          pages: 0,
          subscriptionId: 0,
        ),
      );
      return;
    }

    // Show loading state immediately
    state = const AsyncValue.loading();

    // Debounce: wait 400ms before executing search
    _debounceTimer = Timer(const Duration(milliseconds: 400), () async {
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
    });
  }

  void clearSearch() {
    _debounceTimer?.cancel();
    state = AsyncValue.data(
      const PodcastEpisodeListResponse(
        episodes: [],
        total: 0,
        page: 1,
        size: 20,
        pages: 0,
        subscriptionId: 0,
      ),
    );
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

final profileStatsProvider =
    AsyncNotifierProvider<ProfileStatsNotifier, ProfileStatsModel?>(
      ProfileStatsNotifier.new,
    );
final profileStatsCacheDurationProvider = Provider<Duration>(
  (ref) => const Duration(minutes: 5),
);

class ProfileStatsNotifier extends AsyncNotifier<ProfileStatsModel?> {
  late final PodcastRepository _repository;
  DateTime? _lastLoadedAt;
  Future<ProfileStatsModel?>? _inFlightRequest;

  @override
  FutureOr<ProfileStatsModel?> build() async {
    _repository = ref.read(podcastRepositoryProvider);
    return load(forceRefresh: false);
  }

  bool _isFresh() {
    if (_lastLoadedAt == null) return false;
    final cacheDuration = ref.read(profileStatsCacheDurationProvider);
    return DateTime.now().difference(_lastLoadedAt!) < cacheDuration;
  }

  Future<ProfileStatsModel?> load({bool forceRefresh = false}) async {
    final previousData = state.value;
    if (!forceRefresh && previousData != null && _isFresh()) {
      return previousData;
    }

    final inFlight = _inFlightRequest;
    if (inFlight != null) {
      return inFlight;
    }

    if (previousData == null) {
      state = const AsyncValue.loading();
    }

    final request = () async {
      try {
        final data = await _repository.getProfileStats();
        _lastLoadedAt = DateTime.now();
        state = AsyncValue.data(data);
        return data;
      } catch (error, stackTrace) {
        logger.AppLogger.debug('Failed to load profile stats: $error');
        if (previousData == null) {
          state = AsyncValue.error(error, stackTrace);
        } else {
          state = AsyncValue.data(previousData);
        }
        return previousData;
      } finally {
        _inFlightRequest = null;
      }
    }();

    _inFlightRequest = request;
    return request;
  }
}

final playbackHistoryProvider = FutureProvider<PodcastEpisodeListResponse?>((
  ref,
) async {
  final repository = ref.read(podcastRepositoryProvider);
  try {
    return await repository.getPlaybackHistory(page: 1, size: 100);
  } catch (error) {
    logger.AppLogger.debug('Failed to load playback history: $error');
    return null;
  }
});

final playbackHistoryLiteProvider =
    AsyncNotifierProvider<
      PlaybackHistoryLiteNotifier,
      PlaybackHistoryLiteResponse?
    >(PlaybackHistoryLiteNotifier.new);
final playbackHistoryLiteCacheDurationProvider = Provider<Duration>(
  (ref) => const Duration(minutes: 5),
);

class PlaybackHistoryLiteNotifier
    extends AsyncNotifier<PlaybackHistoryLiteResponse?> {
  late final PodcastRepository _repository;
  DateTime? _lastLoadedAt;
  Future<PlaybackHistoryLiteResponse?>? _inFlightRequest;

  @override
  FutureOr<PlaybackHistoryLiteResponse?> build() async {
    _repository = ref.read(podcastRepositoryProvider);
    return load(forceRefresh: false);
  }

  bool _isFresh() {
    if (_lastLoadedAt == null) return false;
    final cacheDuration = ref.read(playbackHistoryLiteCacheDurationProvider);
    return DateTime.now().difference(_lastLoadedAt!) < cacheDuration;
  }

  Future<PlaybackHistoryLiteResponse?> load({bool forceRefresh = false}) async {
    final previousData = state.value;
    if (!forceRefresh && previousData != null && _isFresh()) {
      return previousData;
    }

    final inFlight = _inFlightRequest;
    if (inFlight != null) {
      return inFlight;
    }

    if (previousData == null) {
      state = const AsyncValue.loading();
    }

    final request = () async {
      try {
        final data = await _repository.getPlaybackHistoryLite(
          page: 1,
          size: 100,
        );
        _lastLoadedAt = DateTime.now();
        state = AsyncValue.data(data);
        return data;
      } catch (error, stackTrace) {
        logger.AppLogger.debug('Failed to load playback history lite: $error');
        if (previousData == null) {
          state = AsyncValue.error(error, stackTrace);
        } else {
          state = AsyncValue.data(previousData);
        }
        return previousData;
      } finally {
        _inFlightRequest = null;
      }
    }();

    _inFlightRequest = request;
    return request;
  }
}

// === Episode Detail Provider ===
final episodeDetailProvider =
    FutureProvider.family<PodcastEpisodeDetailResponse?, int>((
      ref,
      episodeId,
    ) async {
      final repository = ref.read(podcastRepositoryProvider);
      try {
        return await repository.getEpisode(episodeId);
      } catch (error) {
        logger.AppLogger.debug('Failed to load episode detail: $error');
        return null;
      }
    });

// For Riverpod 3.0.3, we need to use a different approach for family providers
// Let's use a simple Notifier and pass the subscriptionId through methods
final podcastEpisodesProvider =
    NotifierProvider<PodcastEpisodesNotifier, PodcastEpisodesState>(
      PodcastEpisodesNotifier.new,
    );

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
    bool? hasSummary,
    bool forceRefresh = false,
  }) async {
    final normalizedStatus = status?.trim().isEmpty ?? true ? null : status;
    final normalizedHasSummary = hasSummary == true ? true : null;

    // Check if data is fresh and skip refresh if not forced (only for first page)
    if (!forceRefresh &&
        page == 1 &&
        state.isDataFresh() &&
        state.cachedSubscriptionId == subscriptionId &&
        state.cachedStatus == normalizedStatus &&
        state.cachedHasSummary == normalizedHasSummary) {
      logger.AppLogger.debug(
        '[Playback] Using cached episode data for sub $subscriptionId (fresh within 5 min)',
      );
      return;
    }

    logger.AppLogger.debug(
      '[Playback] Loading episodes for subscription $subscriptionId, page $page',
    );

    // When loading first page, clear existing episodes immediately to avoid showing old data
    if (page == 1) {
      logger.AppLogger.debug(
        '[Playback] Clearing old episodes and showing loading state',
      );
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
        hasSummary: normalizedHasSummary,
        isPlayed: normalizedStatus == 'played'
            ? true
            : (normalizedStatus == 'unplayed' ? false : null),
      );

      logger.AppLogger.debug(
        '[Playback] Loaded ${response.episodes.length} episodes for subscription $subscriptionId',
      );

      state = state.copyWith(
        episodes: page == 1
            ? response.episodes
            : [...state.episodes, ...response.episodes],
        hasMore: page < response.pages,
        nextPage: page < response.pages ? page + 1 : null,
        currentPage: page,
        total: response.total,
        isLoading: false,
        cachedSubscriptionId: subscriptionId,
        cachedStatus: normalizedStatus,
        cachedHasSummary: normalizedHasSummary,
        lastRefreshTime: DateTime.now(), // Record refresh time
      );
      logger.AppLogger.debug('[OK] Episode data loaded at ${DateTime.now()}');
    } catch (error) {
      logger.AppLogger.debug('[Error] Failed to load episodes: $error');
      state = state.copyWith(isLoading: false, error: error.toString());
    }
  }

  // Load more episodes for the current subscription
  Future<void> loadMoreEpisodesForSubscription({
    required int subscriptionId,
    String? status,
    bool? hasSummary,
  }) async {
    final currentState = state;
    if (currentState.isLoadingMore || !currentState.hasMore) return;

    final normalizedStatus = status?.trim().isEmpty ?? true ? null : status;
    final effectiveStatus = normalizedStatus ?? currentState.cachedStatus;
    final normalizedHasSummary = hasSummary == true ? true : null;
    final effectiveHasSummary =
        normalizedHasSummary ?? currentState.cachedHasSummary;

    state = state.copyWith(isLoadingMore: true);

    try {
      final response = await _repository.listEpisodes(
        subscriptionId: subscriptionId,
        page: currentState.nextPage ?? 1,
        size: 20,
        hasSummary: effectiveHasSummary,
        isPlayed: effectiveStatus == 'played'
            ? true
            : (effectiveStatus == 'unplayed' ? false : null),
      );

      state = state.copyWith(
        episodes: [...state.episodes, ...response.episodes],
        hasMore: state.nextPage != null && state.nextPage! < response.pages,
        nextPage: state.nextPage != null && state.nextPage! < response.pages
            ? state.nextPage! + 1
            : null,
        isLoadingMore: false,
      );
    } catch (error) {
      state = state.copyWith(isLoadingMore: false, error: error.toString());
    }
  }

  // Refresh episodes for a specific subscription
  Future<void> refreshEpisodesForSubscription({
    required int subscriptionId,
    String? status,
    bool? hasSummary,
  }) async {
    state = const PodcastEpisodesState();
    await loadEpisodesForSubscription(
      subscriptionId: subscriptionId,
      status: status,
      hasSummary: hasSummary,
      forceRefresh: true, // Bypass 5-minute cache check on explicit refresh
    );
  }
}

// Note: Models are defined in separate files. This file only contains providers.
