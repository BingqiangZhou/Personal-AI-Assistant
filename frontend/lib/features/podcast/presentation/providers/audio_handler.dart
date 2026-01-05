import 'package:audio_service/audio_service.dart';
import 'package:audio_session/audio_session.dart';
import 'package:flutter/foundation.dart';
import 'package:just_audio/just_audio.dart';

/// AudioHandler for podcast playback with system media controls
class PodcastAudioHandler extends BaseAudioHandler with SeekHandler {
  final AudioPlayer _player = AudioPlayer();
  String? _currentUrl;
  Duration? _lastBroadcastPosition; // For throttling position broadcasts
  bool _isAudioSessionReady = false; // Track AudioSession readiness

  PodcastAudioHandler() {
    // Setup player event listeners
    _listenPlayerEvents();

    // Initialize with default MediaItem (required for Android)
    mediaItem.add(MediaItem(
      id: 'default',
      title: 'No media',
      artist: 'Unknown',
    ));

    // Initialize playback state with IDLE state (no content loaded yet)
    // Include all necessary fields to avoid copyWith overwriting them
    playbackState.add(PlaybackState(
      controls: [MediaControl.play],
      androidCompactActionIndices: const [0],
      processingState: AudioProcessingState.idle,
      playing: false,
      updatePosition: Duration.zero,
      bufferedPosition: Duration.zero,
      speed: 1.0,
      systemActions: const {
        MediaAction.play,
        MediaAction.pause,
        MediaAction.stop,
        MediaAction.seek,
        MediaAction.rewind,
        MediaAction.fastForward,
      },
    ));

    // CRITICAL: Initialize AudioSession synchronously before any playback
    // We use then() callback to mark when it's ready, but don't block constructor
    _initAudioSession().then((_) {
      _isAudioSessionReady = true;
      if (kDebugMode) {
        debugPrint('✅ AudioSession is ready for playback');
      }
    }).catchError((error) {
      if (kDebugMode) {
        debugPrint('⚠️ AudioSession initialization failed: $error');
      }
    });

    if (kDebugMode) {
      debugPrint('🎵 PodcastAudioHandler initialized');
    }
  }

  // Initialize AudioSession (async method called from constructor)
  Future<void> _initAudioSession() async {
    final session = await AudioSession.instance;
    await session.configure(const AudioSessionConfiguration.music());

    // Listen for audio interruptions (calls, other apps, etc.)
    session.interruptionEventStream.listen((event) {
      if (kDebugMode) {
        debugPrint('🎧 interruption: begin=${event.begin} type=${event.type}');
      }
      if (event.begin) {
        pause();
      } else {
        // Auto-resume after interruption ends (optional)
        // if (event.type == AudioInterruptionType.pause) play();
      }
    });

    // Listen for becoming noisy (headphones unplugged)
    session.becomingNoisyEventStream.listen((_) {
      if (kDebugMode) {
        debugPrint('🎧 becomingNoisy -> pause');
      }
      pause();
    });
  }

  void _listenPlayerEvents() {
    // Listen to player state changes (playing/paused, completed, etc.)
    _player.playerStateStream.listen((state) {
      if (kDebugMode) {
        debugPrint('🎧 PlayerState: ${state.playing} ${state.processingState}');
      }
      _broadcastState();
    });

    // CRITICAL: Listen to position updates and broadcast regularly
    // Android MediaSession needs regular position updates to maintain notification
    // We use a throttled broadcast to avoid excessive updates (every 50ms)
    _player.positionStream.listen((position) {
      final positionMs = position.inMilliseconds;
      // Only broadcast if position changed by at least 50ms or this is first update
      if (_lastBroadcastPosition == null ||
          (positionMs - _lastBroadcastPosition!.inMilliseconds).abs() >= 50) {
        _lastBroadcastPosition = position;
        _broadcastState();
      }
    });

    // Listen to processing state changes
    _player.processingStateStream.listen((state) {
      if (state == ProcessingState.completed) {
        _player.seek(Duration.zero);
        _player.pause();
      }
      _broadcastState();
    });

    // Update duration in mediaItem when available
    _player.durationStream.listen((duration) {
      if (duration != null) {
        if (kDebugMode) {
          debugPrint('🎵 [DURATION STREAM] Duration extracted: ${duration.inMilliseconds}ms');
          debugPrint('   Current MediaItem: ${mediaItem.value?.title ?? "null"}');
          debugPrint('   Current MediaItem.duration: ${mediaItem.value?.duration ?? "null"}');
        }
        if (mediaItem.value != null) {
          final updatedMediaItem = mediaItem.value!.copyWith(duration: duration);
          mediaItem.add(updatedMediaItem);
          if (kDebugMode) {
            debugPrint('   ✅ MediaItem updated with new duration: ${duration.inMilliseconds}ms');
          }
        } else {
          if (kDebugMode) {
            debugPrint('   ⚠️ mediaItem.value is null, cannot update duration');
          }
        }
      } else {
        if (kDebugMode) {
          debugPrint('⚠️ [DURATION STREAM] Duration is null');
        }
      }
    });
  }

  void _broadcastState() {
    final playing = _player.playing;
    final rawProcessingState = _mapProcessingState(_player.processingState);

    // Determine if we have a valid audio source
    final hasSource = _player.audioSource != null;
    final hasSequence = _player.sequenceState.sequence.isNotEmpty;

    // CRITICAL: Map processing state correctly for Android
    // - idle: no content loaded
    // - loading: content is loading
    // - ready: content is loaded and ready to play
    // - playing: content is actively playing (if available in audio_service version)
    // - buffering: content is buffering
    // - completed: content has finished playing
    var processingState = (rawProcessingState == AudioProcessingState.idle && (hasSource || hasSequence))
        ? AudioProcessingState.ready
        : rawProcessingState;

    // NOTE: audio_service uses the 'playing' boolean field to indicate actual playback state
    // The processingState indicates the state of the audio source, not whether it's playing
    // - ready + playing=true = actively playing
    // - ready + playing=false = loaded but paused

    // Build controls list based on current state
    // Show all controls when we have content, even if paused
    final bool hasContent = processingState != AudioProcessingState.idle &&
                           processingState != AudioProcessingState.loading;

    final controls = hasContent
        ? [
            MediaControl.rewind,
            playing ? MediaControl.pause : MediaControl.play,
            MediaControl.fastForward,
          ]
        : [MediaControl.play];

    // Set compact action indices based on available controls
    final androidCompactActionIndices = hasContent
        ? const [0, 1, 2]  // Show all 3 buttons in compact view
        : const [0];       // Show only play button

    if (kDebugMode) {
      debugPrint('🎵 [BROADCAST STATE] ========================================');
      debugPrint('  playing: $playing');
      debugPrint('  processingState: $processingState (raw: $rawProcessingState)');
      debugPrint('  hasSource: $hasSource, hasSequence: $hasSequence, hasContent: $hasContent');
      debugPrint('  position: ${_player.position.inMilliseconds}ms (${_player.position.inSeconds}s)');
      debugPrint('  duration: ${_player.duration?.inMilliseconds ?? 0}ms');
      debugPrint('  speed: ${_player.speed}x');
      debugPrint('  controls: ${controls.map((c) => c.toString()).join(', ')}');
      debugPrint('  compactIndices: $androidCompactActionIndices');
      debugPrint('  mediaItem: ${mediaItem.value?.title ?? "null"}');
      debugPrint('  mediaItem.id: ${mediaItem.value?.id ?? "null"}');
      debugPrint('🎵 [BROADCAST STATE] ========================================');
    }

    // CRITICAL FIX: Create a new PlaybackState instead of using copyWith
    // This ensures all fields are properly set and broadcast to Android
    playbackState.add(PlaybackState(
      controls: controls,
      androidCompactActionIndices: androidCompactActionIndices,
      playing: playing,
      processingState: processingState,
      updatePosition: _player.position,
      bufferedPosition: _player.bufferedPosition,
      speed: _player.speed,
      // Always ensure systemActions is set
      systemActions: const {
        MediaAction.play,
        MediaAction.pause,
        MediaAction.stop,
        MediaAction.seek,
        MediaAction.rewind,
        MediaAction.fastForward,
      },
    ));
  }

  AudioProcessingState _mapProcessingState(ProcessingState state) {
    switch (state) {
      case ProcessingState.idle:
        return AudioProcessingState.idle;
      case ProcessingState.loading:
        return AudioProcessingState.loading;
      case ProcessingState.buffering:
        return AudioProcessingState.buffering;
      case ProcessingState.ready:
        return AudioProcessingState.ready;
      case ProcessingState.completed:
        return AudioProcessingState.completed;
    }
  }

  Future<void> setAudioSource(String url) async {
    try {
      _currentUrl = url;
      await _player.setUrl(url);

      // State will be automatically updated by playbackEventStream
      if (kDebugMode) {
        debugPrint('✅ Audio source set: $url');
      }
    } catch (e) {
      if (kDebugMode) {
        debugPrint('❌ Failed to set audio source: $e');
      }
      rethrow;
    }
  }

  @override
  Future<void> play() async {
    // CRITICAL: Wait for AudioSession to be ready before playing
    // This ensures Android MediaSession framework can properly handle the playback
    if (!_isAudioSessionReady) {
      if (kDebugMode) {
        debugPrint('⏳ Waiting for AudioSession to be ready...');
      }
      // Wait up to 1 second for AudioSession to be ready
      int attempts = 0;
      while (!_isAudioSessionReady && attempts < 10) {
        await Future.delayed(const Duration(milliseconds: 100));
        attempts++;
      }
      if (!_isAudioSessionReady) {
        if (kDebugMode) {
          debugPrint('⚠️ AudioSession not ready after 1 second, proceeding anyway');
        }
      } else {
        if (kDebugMode) {
          debugPrint('✅ AudioSession ready for playback');
        }
      }
    }

    // Self-healing: if source is lost, reload it
    if (_player.audioSource == null && _currentUrl != null) {
      if (kDebugMode) {
        debugPrint('⚕️ Source lost, reloading: $_currentUrl');
      }
      try {
        await _player.setUrl(_currentUrl!);
      } catch (e) {
        if (kDebugMode) {
          debugPrint('❌ Failed to reload source: $e');
        }
        rethrow;
      }
    }

    // Start playback
    await _player.play();

    // CRITICAL FIX: Immediately broadcast state to ensure system controls update without delay
    // This prevents race conditions where UI updates faster than notification
    if (kDebugMode) {
      debugPrint('▶️ play() called, immediately broadcasting state');
    }
    _broadcastState();
  }

  @override
  Future<void> pause() async {
    // Pause playback
    await _player.pause();

    // CRITICAL FIX: Immediately broadcast state to ensure system controls update without delay
    if (kDebugMode) {
      debugPrint('⏸️ pause() called, immediately broadcasting state');
    }
    _broadcastState();
  }

  @override
  Future<void> stop() async {
    await _player.stop();
    await _player.seek(Duration.zero);
  }

  @override
  Future<void> seek(Duration position) async {
    await _player.seek(position);
  }

  @override
  Future<void> rewind() async {
    final currentPosition = _player.position;
    final newPosition = currentPosition - const Duration(seconds: 15);
    await _player.seek(newPosition < Duration.zero ? Duration.zero : newPosition);
  }

  @override
  Future<void> fastForward() async {
    final currentPosition = _player.position;
    final duration = _player.duration ?? Duration.zero;
    final newPosition = currentPosition + const Duration(seconds: 30);
    await _player.seek(newPosition > duration ? duration : newPosition);
  }

  /// Set playback speed
  @override
  Future<void> setSpeed(double speed) async {
    await _player.setSpeed(speed);
  }

  /// Get current position
  Duration get position => _player.position;

  /// Get duration
  Duration? get duration => _player.duration;

  /// Get playing state
  bool get playing => _player.playing;

  /// Get player state stream
  Stream<PlayerState> get playerStateStream => _player.playerStateStream;

  /// Get position stream
  Stream<Duration> get positionStream => _player.positionStream;

  /// Get duration stream
  Stream<Duration?> get durationStream => _player.durationStream;

  @override
  Future<void> onTaskRemoved() async {
    // Called when user swipes app away from recent apps
    // Stop playback and release resources
    await stop();
    await super.onTaskRemoved();
  }

  Future<void> dispose() async {
    try {
      // Stop playback first
      await _player.stop();

      // Release all player resources
      await _player.dispose();

      if (kDebugMode) {
        debugPrint('✅ AudioHandler disposed successfully');
      }
    } catch (e) {
      if (kDebugMode) {
        debugPrint('⚠️ Error disposing AudioHandler: $e');
      }
    }
  }
}
