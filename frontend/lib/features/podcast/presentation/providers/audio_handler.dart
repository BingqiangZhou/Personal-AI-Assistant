import 'dart:async';

import 'package:audio_service/audio_service.dart';
import 'package:flutter/foundation.dart';
import 'package:just_audio/just_audio.dart';

/// AudioHandler for podcast playback with system media controls
/// Optimized for Android 15 + Vivo OriginOS with proper state synchronization
class PodcastAudioHandler extends BaseAudioHandler with SeekHandler {
  // Use just_audio's automatic interruption handling
  final AudioPlayer _player = AudioPlayer(handleInterruptions: true);
  String? _currentUrl;

  // Position broadcast throttling fields
  DateTime _lastPosEmit = DateTime.fromMillisecondsSinceEpoch(0);
  Duration _lastPos = Duration.zero;
  Duration _lastBuffered = Duration.zero;

  bool _isDisposed = false; // Track disposal state

  // All stream subscriptions to be cancelled on disposal
  final List<StreamSubscription> _subs = [];

  /// Validate and sanitize artUri for Vivo/OriginOS lock screen compatibility
  /// Only returns http/https URLs, returns null for invalid protocols
  static Uri? _validateArtUri(String? urlString) {
    if (urlString == null || urlString.isEmpty) return null;

    final uri = Uri.tryParse(urlString);
    if (uri == null) return null;

    // Vivo/OriginOS lock screen ONLY supports http/https protocols
    // Reject asset://, file://, content://, and other schemes
    if (uri.scheme != 'http' && uri.scheme != 'https') {
      if (kDebugMode) {
        debugPrint(
          '⚠️ [ART_URI] Invalid scheme: ${uri.scheme} (only http/https allowed)',
        );
      }
      return null;
    }

    return uri;
  }

  PodcastAudioHandler() {
    // Setup player event listeners
    _listenPlayerEvents();

    // Initialize with default MediaItem
    mediaItem.add(
      MediaItem(
        id: 'default',
        title: 'No media',
        artist: 'Unknown',
      ),
    );

    // Initialize playback state
    playbackState.add(
      PlaybackState(
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
      ),
    );

    if (kDebugMode) {
      debugPrint('🎵 PodcastAudioHandler initialized');
    }
  }

  void _listenPlayerEvents() {
    // Listen to player state changes (playing/paused, completed, etc.)
    _subs.add(_player.playerStateStream.listen((state) {
      if (_isDisposed) return;
      if (kDebugMode) {
        debugPrint('🎧 PlayerState: ${state.playing} ${state.processingState}');
      }
      _broadcastState();
    }));

    // CRITICAL: Listen to position updates with optimized throttling
    // Throttled to 500ms to reduce CPU usage and prevent state conflicts on Vivo devices
    // Only calls _broadcastPosition() (lightweight) instead of _broadcastState()
    _subs.add(_player.positionStream.listen((pos) {
      if (_isDisposed) return;
      final now = DateTime.now();
      final dt = now.difference(_lastPosEmit).inMilliseconds;
      final dp = (pos - _lastPos).abs().inMilliseconds;

      // Throttle: 500ms OR position change >= 1000ms
      if (dt < 500 && dp < 1000) return;

      _lastPosEmit = now;
      _lastPos = pos;
      _broadcastPosition(position: pos);
    }));

    // Listen to buffered position changes (optional but recommended)
    // Throttled to match positionStream for consistency
    _subs.add(_player.bufferedPositionStream.listen((buf) {
      if (_isDisposed) return;
      if ((buf - _lastBuffered).abs().inMilliseconds < 1000) return;
      _lastBuffered = buf;
      _broadcastPosition(buffered: buf);
    }));

    // Listen to processing state changes - ONLY handle completed here
    // Don't call _broadcastState() here to avoid duplicate broadcasts
    // (playerStateStream already handles state broadcasts)
    _subs.add(_player.processingStateStream.listen((state) async {
      if (_isDisposed) return;
      if (state == ProcessingState.completed) {
        await _player.seek(Duration.zero);
        await _player.pause();
        _broadcastState(); // Only broadcast on completion
      }
    }));

    // Update duration in mediaItem when available with URL validation
    // CRITICAL: Prevent duration "cross-contamination" between episodes
    _subs.add(_player.durationStream.listen((duration) {
      if (_isDisposed) return;
      final mi = mediaItem.value;
      if (duration == null || mi == null) return;

      // Check if this duration belongs to current URL using extras['url']
      final miUrl = mi.extras?['url'] as String?;

      if (kDebugMode) {
        debugPrint('⏱️ [DURATION STREAM] Duration available: ${duration.inMilliseconds}ms');
        debugPrint('  MediaItem.id: ${mi.id}');
        debugPrint('  MediaItem.title: ${mi.title}');
        debugPrint('  MediaItem.url (from extras): $miUrl');
        debugPrint('  Current URL (_currentUrl): $_currentUrl');
      }

      // CRITICAL: URL validation to prevent cross-contamination
      if (miUrl != null && _currentUrl != null && miUrl != _currentUrl) {
        // Duration arrived late and we've already switched to another URL
        // Discard to prevent showing wrong duration on lock screen
        if (kDebugMode) {
          debugPrint('⚠️ [DURATION] URL MISMATCH - Discarding stale duration!');
          debugPrint('  ❌ Old MediaItem URL: $miUrl');
          debugPrint('  ❌ New current URL: $_currentUrl');
          debugPrint('  ✅ Duration discarded to prevent cross-contamination');
        }
        return;
      }

      // URLs match (or both null) - safe to update duration
      // Only update if duration actually changed
      if (mi.duration != duration) {
        mediaItem.add(mi.copyWith(duration: duration));
        if (kDebugMode) {
          debugPrint('✅ [DURATION] Updated MediaItem:');
          debugPrint('  id: ${mi.id}');
          debugPrint('  title: ${mi.title}');
          debugPrint('  duration: ${duration.inMilliseconds}ms (${duration.inSeconds}s)');
        }
      } else {
        if (kDebugMode) {
          debugPrint('ℹ️ [DURATION] No change - duration already ${duration.inMilliseconds}ms');
        }
      }
    }));
  }

  /// Lightweight position-only broadcast (avoid full state rebuild)
  /// Called frequently (500ms throttled) by positionStream
  /// NOTE: updateTime is only set in _broadcastState() for full state updates
  void _broadcastPosition({Duration? position, Duration? buffered}) {
    if (_isDisposed) return;
    final pos = position ?? _player.position;
    final buf = buffered ?? _player.bufferedPosition;

    // Use copyWith for lightweight update - only update position-related fields
    // NOTE: copyWith doesn't support updateTime, it's only set in _broadcastState()
    final currentState = playbackState.value;
    playbackState.add(
      currentState.copyWith(
        updatePosition: pos,
        bufferedPosition: buf,
        speed: _player.speed,
      ),
    );
  }

  /// Full state broadcast (controls, playing, processingState)
  /// Called infrequently (state changes only) by playerStateStream
  /// CRITICAL: Includes updateTime and safely accesses all nullable fields
  void _broadcastState() {
    if (_isDisposed) return;
    final playing = _player.playing;
    final rawProcessingState = _mapProcessingState(_player.processingState);
    final updateTime = DateTime.now();

    // CRITICAL: Safely access sequenceState to prevent crashes
    // Different just_audio versions may have different nullability behavior
    final hasSource = _player.audioSource != null;
    final sequenceState = _player.sequenceState;
    final hasSequence = sequenceState.sequence.isNotEmpty;

    // Use raw processing state directly (no idle->ready override)
    final processingState = rawProcessingState;

    // Build controls list based on current state
    final bool hasContent =
        processingState != AudioProcessingState.idle &&
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
        ? const [0, 1, 2] // Show all 3 buttons in compact view
        : const [0]; // Show only play button

    if (kDebugMode) {
      debugPrint(
        '🎵 [BROADCAST STATE] ========================================',
      );
      debugPrint('  playing: $playing');
      debugPrint('  processingState: $processingState');
      debugPrint(
        '  hasSource: $hasSource, hasSequence: $hasSequence, hasContent: $hasContent',
      );
      debugPrint('  position: ${_player.position.inMilliseconds}ms');
      debugPrint('  duration: ${_player.duration?.inMilliseconds ?? 0}ms');
      debugPrint('  speed: ${_player.speed}x');
      debugPrint('  updateTime: $updateTime');
      debugPrint('  controls: ${controls.map((c) => c.label).join(', ')}');
      debugPrint(
        '🎵 [BROADCAST STATE] ========================================',
      );
    }

    // Create new PlaybackState with full state update including updateTime
    playbackState.add(
      PlaybackState(
        controls: controls,
        androidCompactActionIndices: androidCompactActionIndices,
        playing: playing,
        processingState: processingState,
        updatePosition: _player.position,
        bufferedPosition: _player.bufferedPosition,
        speed: _player.speed,
        updateTime: updateTime, // CRITICAL: Required for accurate progress on Android/Vivo
        systemActions: const {
          MediaAction.play,
          MediaAction.pause,
          MediaAction.stop,
          MediaAction.seek,
          MediaAction.rewind,
          MediaAction.fastForward,
        },
      ),
    );
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

  /// NEW: Set episode with full metadata support
  /// This is the recommended way to load audio for proper lock screen display
  Future<void> setEpisode({
    required String id,
    required String url,
    required String title,
    String? artist,
    String? album,
    String? artUri, // Changed to String? for validation
    Duration? durationHint,
    Map<String, dynamic>? extras,
    bool autoPlay = false,
  }) async {
    _currentUrl = url;

    // CRITICAL: Validate artUri - ONLY http/https URLs allowed for Vivo/OriginOS
    // Local asset paths (asset:///) will NOT display on lock screen
    final validArtUri = artUri != null ? _validateArtUri(artUri) : null;

    if (artUri != null && validArtUri == null && kDebugMode) {
      debugPrint(
        '⚠️ [SET_EPISODE] Invalid artUri format: "$artUri" (must be http/https)',
      );
    }

    // 1) Push MediaItem FIRST (lock screen/notification shows correct info immediately)
    // CRITICAL: MediaItem must be set BEFORE loading audio to ensure system UI displays correct metadata
    final newMediaItem = MediaItem(
      id: id,
      title: title,
      artist: artist ?? 'Unknown',
      album: album,
      artUri: validArtUri,
      duration: durationHint,
      extras: <String, dynamic>{
        'url': url, // Store URL to prevent duration cross-contamination
        ...?extras,
      },
    );

    mediaItem.add(newMediaItem);

    if (kDebugMode) {
      debugPrint('📋 [MediaItem] Set BEFORE audio load:');
      debugPrint('  id: ${newMediaItem.id}');
      debugPrint('  title: ${newMediaItem.title}');
      debugPrint('  artist: ${newMediaItem.artist}');
      debugPrint('  artUri: ${newMediaItem.artUri ?? "NULL"}');
      debugPrint('  duration: ${newMediaItem.duration?.inMilliseconds ?? "NULL"}ms');
      debugPrint('  url: $url');
    }

    // 2) Then setUrl (triggers durationStream / processingState updates)
    try {
      await _player.setUrl(url);
      if (kDebugMode) {
        debugPrint(
          '✅ Audio source loaded: $title${validArtUri != null ? ' with cover' : ' (no cover)'}',
        );
      }
    } catch (e) {
      if (kDebugMode) {
        debugPrint('❌ Failed to load audio source: $e');
      }
      rethrow;
    }

    // 3) Broadcast state immediately (buttons/controls refresh right away)
    _broadcastState();

    if (autoPlay) {
      await play();
    }
  }

  /// Legacy method for backward compatibility
  /// Consider migrating to setEpisode() for better metadata support
  @Deprecated(
    'Use setEpisode() with full metadata for proper lock screen display',
  )
  Future<void> setAudioSource(String url) async {
    _currentUrl = url;

    // Update MediaItem with minimal info for lock screen display
    mediaItem.add(
      MediaItem(
        id: url, // Use URL as ID for uniqueness
        title: 'Audio Playback',
        artist: 'Unknown',
        extras: <String, dynamic>{'url': url},
      ),
    );

    try {
      await _player.setUrl(url);

      // Broadcast state to update controls
      _broadcastState();

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
    if (_isDisposed) {
      if (kDebugMode) {
        debugPrint('⚠️ play() called after disposal, ignoring');
      }
      return;
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

    // CRITICAL: Check again before actually playing
    // Prevents race condition with stopService()
    if (_isDisposed) {
      if (kDebugMode) {
        debugPrint('⚠️ Disposed during play(), aborting');
      }
      return;
    }

    // Start playback
    try {
      await _player.play();
      if (kDebugMode) {
        debugPrint('▶️ Playback started');
      }
    } catch (e) {
      if (kDebugMode) {
        debugPrint('❌ Failed to start playback: $e');
      }
      rethrow;
    }
  }

  @override
  Future<void> pause() async {
    if (_isDisposed) {
      if (kDebugMode) {
        debugPrint('⚠️ pause() called after disposal, ignoring');
      }
      return;
    }

    await _player.pause();

    if (kDebugMode) {
      debugPrint('⏸️ Playback paused');
    }

    _broadcastState();
  }

  @override
  Future<void> stop() async {
    if (_isDisposed) {
      if (kDebugMode) {
        debugPrint('⚠️ stop() called after disposal, ignoring');
      }
      return;
    }

    if (kDebugMode) {
      debugPrint('⏹️ stop() called - stopping playback');
    }

    await _player.stop();
    await _player.seek(Duration.zero);

    if (kDebugMode) {
      debugPrint('✅ stop() completed');
    }
  }

  /// Complete stop - stops playback AND stops the AudioService
  /// Call this when the app is being closed/destroyed
  Future<void> stopService() async {
    if (_isDisposed) return;
    _isDisposed = true;

    if (kDebugMode) {
      debugPrint('🛑 stopService() called - stopping AudioService');
    }

    // Cancel all subscriptions FIRST to prevent any new events
    for (final s in _subs) {
      await s.cancel();
    }
    _subs.clear();

    // Stop and dispose player
    try {
      await _player.stop();
      await _player.dispose();
    } catch (e) {
      if (kDebugMode) {
        debugPrint('⚠️ Error disposing player: $e');
      }
    }

    // Stop the foreground service BEFORE clearing state
    // This prevents platform messages after service shutdown
    try {
      await super.stop();
      if (kDebugMode) {
        debugPrint('✅ AudioService stopped');
      }
    } catch (e) {
      if (kDebugMode) {
        debugPrint('⚠️ Error stopping service: $e');
      }
    }

    // Clear MediaSession state AFTER stopping service
    // Wrapped in try-catch to handle potential FlutterJNI detachment
    try {
      playbackState.add(
        PlaybackState(
          controls: [],
          systemActions: const {},
          processingState: AudioProcessingState.idle,
          playing: false,
        ),
      );
      mediaItem.add(null);
    } catch (e) {
      // Ignore errors - service already stopped, state clearing is best-effort
      if (kDebugMode) {
        debugPrint('ℹ️ State clearing after stop (expected): $e');
      }
    }

    if (kDebugMode) {
      debugPrint('✅ stopService() completed');
    }
  }

  @override
  Future<void> seek(Duration position) async {
    await _player.seek(position);
    // CRITICAL: Immediately sync position to lock screen after seek
    _broadcastPosition(position: position);
  }

  @override
  Future<void> rewind() async {
    final currentPosition = _player.position;
    final newPosition = currentPosition - const Duration(seconds: 15);
    final clampedPosition = newPosition < Duration.zero
        ? Duration.zero
        : newPosition;
    await _player.seek(clampedPosition);
    // Sync position after rewind
    _broadcastPosition(position: clampedPosition);
  }

  @override
  Future<void> fastForward() async {
    final currentPosition = _player.position;
    final duration = _player.duration ?? Duration.zero;
    final newPosition = currentPosition + const Duration(seconds: 30);
    final clampedPosition = newPosition > duration ? duration : newPosition;
    await _player.seek(clampedPosition);
    // Sync position after fast forward
    _broadcastPosition(position: clampedPosition);
  }

  @override
  Future<void> setSpeed(double speed) async {
    await _player.setSpeed(speed);
    // CRITICAL: Sync speed to lock screen/notification immediately
    _broadcastPosition();
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
    if (kDebugMode) {
      debugPrint('🗑️ Task removed - stopping service and cleaning up');
    }
    // CRITICAL: Must call stopService() to stop foreground service
    // This allows the process to exit properly
    await stopService();
  }

  Future<void> dispose() async {
    // Prevent double-dispose
    if (_isDisposed) {
      return;
    }

    _isDisposed = true;

    if (kDebugMode) {
      debugPrint('🗑️ Disposing AudioHandler...');
    }

    // Cancel all stream subscriptions
    final subCount = _subs.length;
    for (final s in _subs) {
      await s.cancel();
    }
    _subs.clear();

    if (kDebugMode) {
      debugPrint('   - $subCount subscriptions cancelled');
    }

    // Release AudioPlayer
    try {
      await _player.dispose();
      if (kDebugMode) {
        debugPrint('   - Audio player disposed');
      }
    } catch (e) {
      if (kDebugMode) {
        debugPrint('   - Error disposing player: $e');
      }
    }

    if (kDebugMode) {
      debugPrint('✅ AudioHandler disposed');
    }
  }
}
