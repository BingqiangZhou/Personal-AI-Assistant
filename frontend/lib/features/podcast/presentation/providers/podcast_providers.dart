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

class AudioPlayerNotifier extends Notifier<AudioPlayerState> {
  late PodcastRepository _repository;
  bool _isDisposed = false;
  bool _isPlayingEpisode = false;
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
          '馃幍 Playback state changed: ${_lastPlayingState == null
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
              '馃幍 [DURATION UPDATE] ${currentDuration}ms -> ${newDuration}ms (from audio stream)',
            );
          }
          state = state.copyWith(duration: newDuration);
        }
      }
    });

    if (kDebugMode) {
      logger.AppLogger.debug('馃幍 Audio listeners set up successfully');
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
      logger.AppLogger.debug('😴 Sleep timer: stop after episode triggered');
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
      logger.AppLogger.debug('❌ Failed to advance queue on completion: $error');
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

  Future<void> playEpisode(
    PodcastEpisodeModel episode, {
    PlaySource source = PlaySource.direct,
    int? queueEpisodeId,
  }) async {
    if (_isPlayingEpisode) {
      logger.AppLogger.debug(
        '鈿狅笍 playEpisode already in progress, ignoring duplicate call',
      );
      return;
    }

    final isSameEpisode = state.currentEpisode?.id == episode.id;
    final isCompleted = state.processingState == ProcessingState.completed;
    if (isSameEpisode && !isCompleted) {
      if (state.isPlaying) {
        logger.AppLogger.debug(
          '鈴笍 Same episode already playing, skip reloading source',
        );
        return;
      }
      logger.AppLogger.debug(
        '鈴笍 Same episode paused, fast resume without reloading source',
      );
      await resume();
      return;
    }

    _isPlayingEpisode = true;

    try {
      var effectiveSource = source;
      var effectiveQueueEpisodeId = queueEpisodeId;

      if (source == PlaySource.direct) {
        final preparedQueue = await _prepareManualPlayQueue(episode.id);
        if (preparedQueue != null) {
          effectiveSource = PlaySource.queue;
          effectiveQueueEpisodeId = episode.id;
        }
      }
      logger.AppLogger.debug('馃幍 ===== playEpisode called =====');
      logger.AppLogger.debug('馃幍 Episode ID: ${episode.id}');
      logger.AppLogger.debug('馃幍 Episode Title: ${episode.title}');
      logger.AppLogger.debug('馃幍 Audio URL: ${episode.audioUrl}');
      logger.AppLogger.debug('馃幍 Subscription ID: ${episode.subscriptionId}');

      if (!ref.mounted || _isDisposed) {
        _isPlayingEpisode = false;
        return;
      }

      final queueSnapshot = state.queue;
      final queueSyncing = state.queueSyncing;
      var targetPlaybackRate = state.playbackRate;

      try {
        final effectiveRate = await _repository.getEffectivePlaybackRate(
          subscriptionId: episode.subscriptionId,
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
      logger.AppLogger.debug('鈴革笍 Step 1: Pausing current playback');
      try {
        await _audioHandler.pause();
        logger.AppLogger.debug('  鉁?Paused');
      } catch (e) {
        logger.AppLogger.debug('  鈿狅笍 Pause error (ignorable): $e');
      }

      state = const AudioPlayerState().copyWith(
        playbackRate: targetPlaybackRate,
        queue: queueSnapshot,
        queueSyncing: queueSyncing,
        playSource: effectiveSource,
        currentQueueEpisodeId: effectiveSource == PlaySource.queue
            ? (effectiveQueueEpisodeId ?? episode.id)
            : null,
      );

      if (!ref.mounted || _isDisposed) return;

      // ===== STEP 2: Set new episode info with duration from backend =====
      logger.AppLogger.debug('馃摑 Step 2: Setting new episode info');
      // CRITICAL: Backend audioDuration is in SECONDS, convert to MILLISECONDS
      final durationMs = (episode.audioDuration ?? 0) * 1000;
      final resumePositionMs = normalizeResumePositionMs(
        episode.playbackPosition,
        episode.audioDuration,
      );
      logger.AppLogger.debug(
        '  馃搳 Using backend duration: ${episode.audioDuration}s = ${durationMs}ms',
      );
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
      logger.AppLogger.debug('馃攧 Step 3: Setting new episode with metadata');
      logger.AppLogger.debug(
        '  馃搳 Backend duration already set: ${state.duration}ms',
      );
      logger.AppLogger.debug('  馃柤锔?Image URL: ${episode.imageUrl ?? "NULL"}');

      try {
        await _audioHandler.setEpisode(
          id: episode.id.toString(),
          url: episode.audioUrl,
          title: episode.title,
          artist: episode.subscriptionTitle ?? 'Unknown Podcast',
          artUri: episode.imageUrl, // Will be validated inside setEpisode()
          autoPlay:
              false, // We'll manually start playback after restoring position/speed
        );
        logger.AppLogger.debug('  鉁?Episode loaded successfully');
      } catch (loadError) {
        logger.AppLogger.debug('  鉂?Failed to load episode: $loadError');
        throw Exception('Failed to load audio: $loadError');
      }

      if (!ref.mounted || _isDisposed) return;

      // ===== STEP 4: Restore playback position =====
      if (resumePositionMs > 0) {
        logger.AppLogger.debug(
          '鈴?Step 4: Seeking to saved position: ${resumePositionMs}ms',
        );
        try {
          await _audioHandler.seek(Duration(milliseconds: resumePositionMs));
          logger.AppLogger.debug('  鉁?Seek completed');
        } catch (e) {
          logger.AppLogger.debug('  鈿狅笍 Seek error: $e');
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
      logger.AppLogger.debug('鈻讹笍 Step 6: Starting playback');
      try {
        await _audioHandler.play();
        logger.AppLogger.debug('  鉁?Playback started');

        if (ref.mounted && !_isDisposed) {
          state = state.copyWith(
            isPlaying: true,
            isLoading: false,
            position: resumePositionMs,
            playbackRate: targetPlaybackRate,
          );
        }
      } catch (playError) {
        logger.AppLogger.debug('  鉂?Failed to start playback: $playError');
        _isPlayingEpisode = false;
        throw Exception('Failed to start playback: $playError');
      }

      logger.AppLogger.debug('馃幍 ===== playEpisode completed =====');

      // Update playback state on server (non-blocking)
      if (ref.mounted && !_isDisposed) {
        _updatePlaybackStateOnServer().catchError((error) {
          logger.AppLogger.debug('鈿狅笍 Server update failed: $error');
        });
      }

      // Release the lock
      _isPlayingEpisode = false;
    } catch (error) {
      logger.AppLogger.debug('鉂?===== Failed to play episode =====');
      logger.AppLogger.debug('鉂?Episode ID: ${episode.id}');
      logger.AppLogger.debug('鉂?Audio URL: ${episode.audioUrl}');
      logger.AppLogger.debug('鉂?Error: $error');

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
        '馃敶 pause() called, current isPlaying: ${state.isPlaying}',
      );

      // IMPORTANT: Don't manually update state here - let the playbackState listener handle it
      // The listener will update the state when playbackState.playing changes
      // This avoids race conditions where manual state gets overwritten

      await _audioHandler.pause();
      logger.AppLogger.debug(
        '馃敶 AudioHandler.pause() completed, waiting for playbackState listener to update UI',
      );

      if (ref.mounted && !_isDisposed) {
        await _updatePlaybackStateOnServer(immediate: true);
      }
    } catch (error) {
      logger.AppLogger.debug('鉂?pause() error: $error');
      if (ref.mounted && !_isDisposed) {
        state = state.copyWith(error: error.toString());
      }
    }
  }

  Future<void> resume() async {
    if (_isDisposed) return;

    try {
      logger.AppLogger.debug(
        '馃煝 resume() called, current isPlaying: ${state.isPlaying}',
      );

      // IMPORTANT: Don't manually update state here - let the playbackState listener handle it
      // The listener will update the state when playbackState.playing changes
      // This avoids race conditions where manual state gets overwritten

      await _audioHandler.play();
      logger.AppLogger.debug(
        '馃煝 AudioHandler.play() completed, waiting for playbackState listener to update UI',
      );

      if (ref.mounted && !_isDisposed) {
        unawaited(
          _updatePlaybackStateOnServer().catchError((error) {
            logger.AppLogger.debug(
              '鈿狅笍 Server update failed after resume: $error',
            );
          }),
        );
      }
    } catch (error) {
      logger.AppLogger.debug('鉂?resume() error: $error');
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

    logger.AppLogger.debug('😴 Sleep timer set: ${duration.inMinutes} minutes');

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

    logger.AppLogger.debug('😴 Sleep timer set: after current episode');
  }

  void cancelSleepTimer() {
    if (_isDisposed || !ref.mounted) return;

    _sleepTimerTickTimer?.cancel();
    _sleepTimerTickTimer = null;

    state = state.copyWith(clearSleepTimer: true);

    logger.AppLogger.debug('😴 Sleep timer cancelled');
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
      logger.AppLogger.debug('😴 Sleep timer expired, pausing playback');
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
        '鈿狅笍 Failed to update playback state on server: $error',
      );
      logger.AppLogger.debug('馃搷 Episode ID: ${episode.id}');
      logger.AppLogger.debug(
        '馃搷 Position: ${state.position}ms (${(state.position / 1000).round()}s)',
      );
      logger.AppLogger.debug('馃搷 Is Playing: ${state.isPlaying}');
      logger.AppLogger.debug('馃搷 Playback Rate: ${state.playbackRate}');

      // Check if it's an authentication error
      if (error.toString().contains('401') ||
          error.toString().contains('authentication')) {
        logger.AppLogger.debug(
          '馃攽 Authentication error - user may need to log in again',
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

  @override
  FutureOr<PodcastQueueModel> build() async {
    _repository = ref.read(podcastRepositoryProvider);
    try {
      final queue = await _repository.getQueue();
      ref.read(audioPlayerProvider.notifier).syncQueueState(queue);
      return queue;
    } catch (_) {
      return PodcastQueueModel.empty();
    }
  }

  Future<PodcastQueueModel> loadQueue() async {
    ref.read(audioPlayerProvider.notifier).setQueueSyncing(true);
    try {
      final queue = await _repository.getQueue();
      state = AsyncValue.data(queue);
      ref.read(audioPlayerProvider.notifier).syncQueueState(queue);
      return queue;
    } catch (error, stackTrace) {
      state = AsyncValue.error(error, stackTrace);
      rethrow;
    } finally {
      ref.read(audioPlayerProvider.notifier).setQueueSyncing(false);
    }
  }

  Future<PodcastQueueModel> addToQueue(int episodeId) async {
    ref.read(audioPlayerProvider.notifier).setQueueSyncing(true);
    try {
      final queue = await _repository.addQueueItem(episodeId);
      state = AsyncValue.data(queue);
      ref.read(audioPlayerProvider.notifier).syncQueueState(queue);
      return queue;
    } catch (error, stackTrace) {
      state = AsyncValue.error(error, stackTrace);
      rethrow;
    } finally {
      ref.read(audioPlayerProvider.notifier).setQueueSyncing(false);
    }
  }

  Future<PodcastQueueModel> removeFromQueue(int episodeId) async {
    ref.read(audioPlayerProvider.notifier).setQueueSyncing(true);
    try {
      final queue = await _repository.removeQueueItem(episodeId);
      state = AsyncValue.data(queue);
      ref.read(audioPlayerProvider.notifier).syncQueueState(queue);
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
      state = AsyncValue.data(queue);
      ref.read(audioPlayerProvider.notifier).syncQueueState(queue);
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
      state = AsyncValue.data(queue);
      ref.read(audioPlayerProvider.notifier).syncQueueState(queue);
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
    state = AsyncValue.data(queue);
    ref.read(audioPlayerProvider.notifier).syncQueueState(queue);
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
        '馃摝 Using cached subscription data (fresh within 5 min)',
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
        '鉁?Subscription data loaded at ${DateTime.now()} (total=${response.total}, count=${response.subscriptions.length})',
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
        '馃棏锔?Bulk delete request: subscriptionIds=$subscriptionIds',
      );
      logger.AppLogger.debug(
        '馃棏锔?Subscription IDs type: ${subscriptionIds.runtimeType}',
      );

      final response = await _repository.bulkDeleteSubscriptions(
        subscriptionIds: subscriptionIds,
      );

      logger.AppLogger.debug(
        '鉁?Bulk delete success: ${response.successCount} deleted, ${response.failedCount} failed',
      );

      // Refresh the list
      await refreshSubscriptions();

      return response;
    } catch (error) {
      logger.AppLogger.debug('鉂?Bulk delete failed: $error');
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

  @override
  PodcastFeedState build() {
    _repository = ref.read(podcastRepositoryProvider);
    return const PodcastFeedState();
  }

  Future<void> loadInitialFeed() async {
    state = state.copyWith(isLoading: true, error: null);

    try {
      final response = await _repository.getPodcastFeed(page: 1, pageSize: 20);

      state = state.copyWith(
        episodes: response.items,
        hasMore: response.hasMore,
        nextPage: response.nextPage,
        total: response.total,
        isLoading: false,
      );
    } catch (error) {
      logger.AppLogger.debug('鉂?鍔犺浇鏈€鏂板唴瀹瑰け璐? $error');

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
        error: '鍔犺浇鏈€鏂板唴瀹瑰け璐? ${error.toString()}',
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
      logger.AppLogger.debug('鉂?鍔犺浇鏇村鍐呭澶辫触: $error');

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
        error: '鍔犺浇鏇村鍐呭澶辫触: ${error.toString()}',
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
    bool forceRefresh = false,
  }) async {
    // Check if data is fresh and skip refresh if not forced (only for first page)
    if (!forceRefresh && page == 1 && state.isDataFresh()) {
      logger.AppLogger.debug(
        '馃摝 Using cached episode data for sub $subscriptionId (fresh within 5 min)',
      );
      return;
    }

    logger.AppLogger.debug(
      '馃搵 Loading episodes for subscription $subscriptionId, page $page',
    );

    // When loading first page, clear existing episodes immediately to avoid showing old data
    if (page == 1) {
      logger.AppLogger.debug(
        '馃搵 Clearing old episodes and showing loading state',
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
        isPlayed: status == 'played'
            ? true
            : (status == 'unplayed' ? false : null),
      );

      logger.AppLogger.debug(
        '馃搵 Loaded ${response.episodes.length} episodes for subscription $subscriptionId',
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
        lastRefreshTime: DateTime.now(), // Record refresh time
      );
      logger.AppLogger.debug('鉁?Episode data loaded at ${DateTime.now()}');
    } catch (error) {
      logger.AppLogger.debug('鉂?Failed to load episodes: $error');
      state = state.copyWith(isLoading: false, error: error.toString());
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
  }) async {
    state = state.copyWith(episodes: []);
    await loadEpisodesForSubscription(
      subscriptionId: subscriptionId,
      status: status,
      forceRefresh: true, // Bypass 5-minute cache check on explicit refresh
    );
  }
}

// Note: Models are defined in separate files. This file only contains providers.
