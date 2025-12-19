import 'package:equatable/equatable.dart';
import 'package:json_annotation/json_annotation.dart';

part 'podcast_playback_model.g.dart';

@JsonSerializable()
class PodcastPlaybackStateResponse extends Equatable {
  @JsonKey(name: 'episode_id')
  final int episodeId;
  @JsonKey(name: 'current_position')
  final int currentPosition;
  @JsonKey(name: 'is_playing')
  final bool isPlaying;
  @JsonKey(name: 'playback_rate')
  final double playbackRate;
  @JsonKey(name: 'play_count')
  final int playCount;
  @JsonKey(name: 'last_updated_at')
  final DateTime lastUpdatedAt;
  @JsonKey(name: 'progress_percentage')
  final double progressPercentage;
  @JsonKey(name: 'remaining_time')
  final int remainingTime;

  const PodcastPlaybackStateResponse({
    required this.episodeId,
    required this.currentPosition,
    required this.isPlaying,
    required this.playbackRate,
    required this.playCount,
    required this.lastUpdatedAt,
    required this.progressPercentage,
    required this.remainingTime,
  });

  factory PodcastPlaybackStateResponse.fromJson(Map<String, dynamic> json) =>
      _$PodcastPlaybackStateResponseFromJson(json);

  Map<String, dynamic> toJson() => _$PodcastPlaybackStateResponseToJson(this);

  @override
  List<Object?> get props => [
        episodeId,
        currentPosition,
        isPlaying,
        playbackRate,
        playCount,
        lastUpdatedAt,
        progressPercentage,
        remainingTime,
      ];
}

@JsonSerializable()
class PodcastPlaybackUpdateRequest extends Equatable {
  final int position;
  @JsonKey(name: 'is_playing')
  final bool isPlaying;
  @JsonKey(name: 'playback_rate')
  final double playbackRate;

  const PodcastPlaybackUpdateRequest({
    required this.position,
    required this.isPlaying,
    this.playbackRate = 1.0,
  });

  Map<String, dynamic> toJson() => _$PodcastPlaybackUpdateRequestToJson(this);

  @override
  List<Object?> get props => [position, isPlaying, playbackRate];
}

@JsonSerializable()
class PodcastSummaryResponse extends Equatable {
  @JsonKey(name: 'episode_id')
  final int episodeId;
  final String summary;
  final String version;
  @JsonKey(name: 'confidence_score')
  final double? confidenceScore;
  @JsonKey(name: 'transcript_used')
  final bool transcriptUsed;
  @JsonKey(name: 'generated_at')
  final DateTime generatedAt;
  @JsonKey(name: 'word_count')
  final int wordCount;

  const PodcastSummaryResponse({
    required this.episodeId,
    required this.summary,
    required this.version,
    this.confidenceScore,
    required this.transcriptUsed,
    required this.generatedAt,
    required this.wordCount,
  });

  factory PodcastSummaryResponse.fromJson(Map<String, dynamic> json) =>
      _$PodcastSummaryResponseFromJson(json);

  Map<String, dynamic> toJson() => _$PodcastSummaryResponseToJson(this);

  @override
  List<Object?> get props => [
        episodeId,
        summary,
        version,
        confidenceScore,
        transcriptUsed,
        generatedAt,
        wordCount,
      ];
}

@JsonSerializable()
class PodcastSummaryRequest extends Equatable {
  @JsonKey(name: 'force_regenerate')
  final bool forceRegenerate;
  @JsonKey(name: 'use_transcript')
  final bool? useTranscript;

  const PodcastSummaryRequest({
    this.forceRegenerate = false,
    this.useTranscript,
  });

  Map<String, dynamic> toJson() => _$PodcastSummaryRequestToJson(this);

  @override
  List<Object?> get props => [forceRegenerate, useTranscript];
}

@JsonSerializable()
class PodcastStatsResponse extends Equatable {
  @JsonKey(name: 'total_subscriptions')
  final int totalSubscriptions;
  @JsonKey(name: 'total_episodes')
  final int totalEpisodes;
  @JsonKey(name: 'total_playtime')
  final int totalPlaytime;
  @JsonKey(name: 'summaries_generated')
  final int summariesGenerated;
  @JsonKey(name: 'pending_summaries')
  final int pendingSummaries;
  @JsonKey(name: 'recently_played')
  final List<Map<String, dynamic>> recentlyPlayed;
  @JsonKey(name: 'top_categories')
  final List<Map<String, dynamic>> topCategories;
  @JsonKey(name: 'listening_streak')
  final int listeningStreak;

  const PodcastStatsResponse({
    required this.totalSubscriptions,
    required this.totalEpisodes,
    required this.totalPlaytime,
    required this.summariesGenerated,
    required this.pendingSummaries,
    required this.recentlyPlayed,
    required this.topCategories,
    required this.listeningStreak,
  });

  factory PodcastStatsResponse.fromJson(Map<String, dynamic> json) =>
      _$PodcastStatsResponseFromJson(json);

  Map<String, dynamic> toJson() => _$PodcastStatsResponseToJson(this);

  @override
  List<Object?> get props => [
        totalSubscriptions,
        totalEpisodes,
        totalPlaytime,
        summariesGenerated,
        pendingSummaries,
        recentlyPlayed,
        topCategories,
        listeningStreak,
      ];
}

@JsonSerializable()
class PodcastSearchFilter extends Equatable {
  final String? query;
  @JsonKey(name: 'category_id')
  final int? categoryId;
  final String? status;
  @JsonKey(name: 'has_summary')
  final bool? hasSummary;
  @JsonKey(name: 'date_from')
  final DateTime? dateFrom;
  @JsonKey(name: 'date_to')
  final DateTime? dateTo;
  @JsonKey(name: 'subscription_id')
  final int? subscriptionId;
  @JsonKey(name: 'is_played')
  final bool? isPlayed;
  @JsonKey(name: 'duration_min')
  final int? durationMin;
  @JsonKey(name: 'duration_max')
  final int? durationMax;

  const PodcastSearchFilter({
    this.query,
    this.categoryId,
    this.status,
    this.hasSummary,
    this.dateFrom,
    this.dateTo,
    this.subscriptionId,
    this.isPlayed,
    this.durationMin,
    this.durationMax,
  });

  Map<String, dynamic> toJson() => _$PodcastSearchFilterToJson(this);

  @override
  List<Object?> get props => [
        query,
        categoryId,
        status,
        hasSummary,
        dateFrom,
        dateTo,
        subscriptionId,
        isPlayed,
        durationMin,
        durationMax,
      ];
}