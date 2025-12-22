import 'package:equatable/equatable.dart';
import 'podcast_episode_model.dart';

enum ProcessingState {
  idle,
  loading,
  buffering,
  ready,
  completed,
}

// AudioPlayerState model
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
    final hours = duration.inHours;
    final minutes = duration.inMinutes.remainder(60);
    final seconds = duration.inSeconds.remainder(60);
    
    if (hours > 0) {
      return '${hours.toString().padLeft(2, '0')}:${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';
    }
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