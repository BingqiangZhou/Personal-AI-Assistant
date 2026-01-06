import 'package:audio_service/audio_service.dart';
import 'package:audio_session/audio_session.dart';
import 'package:flutter/foundation.dart';
import 'package:just_audio/just_audio.dart';

/// AudioHandler for podcast playback with system media controls
/// Optimized for Android 15 + Vivo OriginOS with proper state synchronization
/// Uses manual audio focus management via audio_session
class PodcastAudioHandler extends BaseAudioHandler with SeekHandler {
  // CRITICAL: Disable just_audio's automatic interruption handling
  // We will manage audio focus manually via audio_session
  final AudioPlayer _player = AudioPlayer(handleInterruptions: false);
  String? _currentUrl;

  // Position broadcast throttling fields
  DateTime _lastPosEmit = DateTime.fromMillisecondsSinceEpoch(0);
  Duration _lastPos = Duration.zero;
  Duration _lastBuffered = Duration.zero;

  bool _isAudioSessionReady = false; // Track AudioSession readiness
  bool _isActive = false; // Track audio focus state
  AudioSession? _session; // AudioSession instance for focus management

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

    // CRITICAL FIX: Initialize with default MediaItem WITHOUT artUri
    // Vivo/OriginOS lock screen does NOT support local asset paths (asset:///)
    // Only network URLs (http/https) are supported for lock screen display
    // The actual podcast cover (network URL) will be set when playing an episode
    mediaItem.add(
      MediaItem(
        id: 'default',
        title: 'No media',
        artist: 'Unknown',
        // artUri: null - Don't use asset paths, Vivo lock screen won't display them
      ),
    );

    // Initialize playback state with IDLE state (no content loaded yet)
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

    // CRITICAL: Initialize AudioSession synchronously before any playback
    _initAudioSession()
        .then((_) {
          _isAudioSessionReady = true;
          if (kDebugMode) {
            debugPrint('✅ AudioSession is ready for playback');
          }
        })
        .catchError((error) {
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
    _session = await AudioSession.instance;

    // CRITICAL: Configure for podcast playback with manual audio focus management
    // Using speech contentType for better Android 15 + Vivo OriginOS compatibility
    // androidAudioFocusGainType.gain = request permanent audio focus
    await _session!.configure(
      const AudioSessionConfiguration.speech().copyWith(
        androidAudioFocusGainType: AndroidAudioFocusGainType.gain,
      ),
    );

    // Listen for audio interruptions (calls, other apps, etc.)
    _session!.interruptionEventStream.listen((event) {
      if (kDebugMode) {
        debugPrint('🎧 ========================================');
        debugPrint('🎧 AUDIO INTERRUPTION DETECTED');
        debugPrint('  begin: ${event.begin}');
        debugPrint('  type: ${event.type}');
        if (event.begin) {
          debugPrint('  Action: Pausing playback and releasing audio focus');
        } else {
          debugPrint('  Action: Interruption ended (not auto-resuming for podcast)');
        }
        debugPrint('🎧 ========================================');
      }

      if (event.begin) {
        // Interruption began - pause playback and release audio focus
        // We release focus so other apps can use it
        pause();
        _releaseAudioFocus();
      }
      // Note: We don't auto-resume for podcasts - user preference
    });

    // Listen for becoming noisy (headphones unplugged)
    _session!.becomingNoisyEventStream.listen((_) {
      if (kDebugMode) {
        debugPrint('🎧 ========================================');
        debugPrint('🎧 AUDIO NOISY EVENT: Headphones unplugged');
        debugPrint('  Action: Pausing playback');
        debugPrint('🎧 ========================================');
      }
      pause();
    });

    if (kDebugMode) {
      debugPrint('✅ AudioSession configured: contentType=speech');
      debugPrint('✅ Manual audio focus management enabled');
      debugPrint('✅ just_audio automatic interruption handling disabled');
    }
  }

  /// Request audio focus before playing
  /// Returns true if focus was granted, false otherwise
  Future<bool> _requestAudioFocus() async {
    if (_isActive) {
      if (kDebugMode) {
        debugPrint('🎵 Audio focus already active');
      }
      return true;
    }

    if (_session == null) {
      if (kDebugMode) {
        debugPrint('⚠️ AudioSession is null, cannot request focus');
      }
      return false;
    }

    try {
      final success = await _session!.setActive(true);
      if (success) {
        _isActive = true;
        if (kDebugMode) {
          debugPrint('🎵 ✅ Audio focus requested and GRANTED');
        }
      } else {
        if (kDebugMode) {
          debugPrint('🎵 ❌ Audio focus request DENIED (e.g., phone call in progress)');
        }
      }
      return success;
    } catch (e) {
      if (kDebugMode) {
        debugPrint('🎵 ⚠️ Error requesting audio focus: $e');
      }
      return false;
    }
  }

  /// Release audio focus when stopping playback
  Future<void> _releaseAudioFocus() async {
    if (!_isActive) {
      if (kDebugMode) {
        debugPrint('🎵 Audio focus already inactive');
      }
      return;
    }

    if (_session == null) {
      if (kDebugMode) {
        debugPrint('⚠️ AudioSession is null, cannot release focus');
      }
      return;
    }

    try {
      await _session!.setActive(false);
      _isActive = false;
      if (kDebugMode) {
        debugPrint('🎵 ✅ Audio focus released');
      }
    } catch (e) {
      if (kDebugMode) {
        debugPrint('🎵 ⚠️ Error releasing audio focus: $e');
      }
    }
  }

  void _listenPlayerEvents() {
    // Listen to player state changes (playing/paused, completed, etc.)
    _player.playerStateStream.listen((state) {
      if (kDebugMode) {
        debugPrint('🎧 PlayerState: ${state.playing} ${state.processingState}');
      }
      _broadcastState();
    });

    // CRITICAL: Listen to position updates with optimized throttling
    // Throttled to 500ms to reduce CPU usage and prevent state conflicts on Vivo devices
    // Only calls _broadcastPosition() (lightweight) instead of _broadcastState()
    _player.positionStream.listen((pos) {
      final now = DateTime.now();
      final dt = now.difference(_lastPosEmit).inMilliseconds;
      final dp = (pos - _lastPos).abs().inMilliseconds;

      // Throttle: 500ms OR position change >= 1000ms
      if (dt < 500 && dp < 1000) return;

      _lastPosEmit = now;
      _lastPos = pos;
      _broadcastPosition(position: pos);
    });

    // Listen to buffered position changes (optional but recommended)
    // Throttled to match positionStream for consistency
    _player.bufferedPositionStream.listen((buf) {
      if ((buf - _lastBuffered).abs().inMilliseconds < 1000) return;
      _lastBuffered = buf;
      _broadcastPosition(buffered: buf);
    });

    // Listen to processing state changes - ONLY handle completed here
    // Don't call _broadcastState() here to avoid duplicate broadcasts
    // (playerStateStream already handles state broadcasts)
    _player.processingStateStream.listen((state) async {
      if (state == ProcessingState.completed) {
        await _player.seek(Duration.zero);
        await _player.pause();
        _broadcastState(); // Only broadcast on completion
      }
    });

    // Update duration in mediaItem when available with URL validation
    // CRITICAL: Prevent duration "cross-contamination" between episodes
    _player.durationStream.listen((duration) {
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
    });
  }

  /// Lightweight position-only broadcast (avoid full state rebuild)
  /// Called frequently (500ms throttled) by positionStream
  /// NOTE: updateTime is only set in _broadcastState() for full state updates
  void _broadcastPosition({Duration? position, Duration? buffered}) {
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
    // CRITICAL: Wait for AudioSession to be ready before playing
    if (!_isAudioSessionReady) {
      if (kDebugMode) {
        debugPrint('⏳ Waiting for AudioSession to be ready...');
      }
      int attempts = 0;
      while (!_isAudioSessionReady && attempts < 10) {
        await Future.delayed(const Duration(milliseconds: 100));
        attempts++;
      }
      if (!_isAudioSessionReady) {
        if (kDebugMode) {
          debugPrint(
            '⚠️ AudioSession not ready after 1 second, proceeding anyway',
          );
        }
      } else {
        if (kDebugMode) {
          debugPrint('✅ AudioSession ready for playback');
        }
      }
    }

    // CRITICAL: Request audio focus BEFORE playing
    // If focus is denied (e.g., phone call in progress), do not play
    final focusGranted = await _requestAudioFocus();
    if (!focusGranted) {
      if (kDebugMode) {
        debugPrint('❌ Cannot play: audio focus request denied');
      }
      // Broadcast state to update UI (showing paused state)
      _broadcastState();
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

    // Start playback - audio focus is already requested manually
    try {
      await _player.play();
      if (kDebugMode) {
        debugPrint('▶️ Playback started (manual audio focus management)');
      }
    } catch (e) {
      if (kDebugMode) {
        debugPrint('❌ Failed to start playback: $e');
      }
      rethrow;
    }

    // NOTE: No need to manually call _broadcastState() here
    // playerStateStream will automatically trigger _broadcastState()
  }

  @override
  Future<void> pause() async {
    // Pause playback but KEEP audio focus
    // This allows quick resume and prevents other apps from stealing focus
    await _player.pause();

    if (kDebugMode) {
      debugPrint('⏸️ pause() completed - audio focus KEPT for quick resume');
    }

    _broadcastState();
  }

  @override
  Future<void> stop() async {
    if (kDebugMode) {
      debugPrint('⏹️ stop() called - releasing audio focus manually');
    }

    await _player.stop();
    await _player.seek(Duration.zero);

    // CRITICAL: Release audio focus when stopping
    await _releaseAudioFocus();

    // CRITICAL: Properly cleanup state when stopping
    playbackState.add(
      playbackState.value.copyWith(
        playing: false,
        processingState: AudioProcessingState.idle,
        updatePosition: Duration.zero,
        bufferedPosition: Duration.zero,
      ),
    );

    await super.stop();

    if (kDebugMode) {
      debugPrint('✅ stop() completed - service fully stopped');
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
    await stop();
    await super.onTaskRemoved();
  }

  Future<void> dispose() async {
    try {
      await _player.stop();
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
