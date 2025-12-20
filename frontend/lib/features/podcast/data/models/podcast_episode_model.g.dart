// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'podcast_episode_model.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

PodcastEpisodeModel _$PodcastEpisodeModelFromJson(Map<String, dynamic> json) =>
    PodcastEpisodeModel(
      id: (json['id'] as num).toInt(),
      subscriptionId: (json['subscription_id'] as num).toInt(),
      title: json['title'] as String,
      description: json['description'] as String?,
      audioUrl: json['audio_url'] as String,
      audioDuration: (json['audio_duration'] as num?)?.toInt(),
      audioFileSize: (json['audio_file_size'] as num?)?.toInt(),
      publishedAt: DateTime.parse(json['published_at'] as String),
      transcriptUrl: json['transcript_url'] as String?,
      transcriptContent: json['transcript_content'] as String?,
      aiSummary: json['ai_summary'] as String?,
      summaryVersion: json['summary_version'] as String?,
      aiConfidenceScore: (json['ai_confidence_score'] as num?)?.toDouble(),
      playCount: (json['play_count'] as num?)?.toInt() ?? 0,
      lastPlayedAt: json['last_played_at'] == null
          ? null
          : DateTime.parse(json['last_played_at'] as String),
      season: (json['season'] as num?)?.toInt(),
      episodeNumber: (json['episode_number'] as num?)?.toInt(),
      explicit: json['explicit'] as bool? ?? false,
      status: json['status'] as String? ?? 'published',
      metadata: json['metadata'] as Map<String, dynamic>?,
      playbackPosition: (json['playback_position'] as num?)?.toInt(),
      isPlaying: json['is_playing'] as bool? ?? false,
      playbackRate: (json['playback_rate'] as num?)?.toDouble() ?? 1.0,
      isPlayed: json['is_played'] as bool? ?? false,
      createdAt: DateTime.parse(json['created_at'] as String),
      updatedAt: json['updated_at'] == null
          ? null
          : DateTime.parse(json['updated_at'] as String),
    );

Map<String, dynamic> _$PodcastEpisodeModelToJson(
  PodcastEpisodeModel instance,
) => <String, dynamic>{
  'id': instance.id,
  'subscription_id': instance.subscriptionId,
  'title': instance.title,
  'description': instance.description,
  'audio_url': instance.audioUrl,
  'audio_duration': instance.audioDuration,
  'audio_file_size': instance.audioFileSize,
  'published_at': instance.publishedAt.toIso8601String(),
  'transcript_url': instance.transcriptUrl,
  'transcript_content': instance.transcriptContent,
  'ai_summary': instance.aiSummary,
  'summary_version': instance.summaryVersion,
  'ai_confidence_score': instance.aiConfidenceScore,
  'play_count': instance.playCount,
  'last_played_at': instance.lastPlayedAt?.toIso8601String(),
  'season': instance.season,
  'episode_number': instance.episodeNumber,
  'explicit': instance.explicit,
  'status': instance.status,
  'metadata': instance.metadata,
  'playback_position': instance.playbackPosition,
  'is_playing': instance.isPlaying,
  'playback_rate': instance.playbackRate,
  'is_played': instance.isPlayed,
  'created_at': instance.createdAt.toIso8601String(),
  'updated_at': instance.updatedAt?.toIso8601String(),
};

PodcastEpisodeListResponse _$PodcastEpisodeListResponseFromJson(
  Map<String, dynamic> json,
) => PodcastEpisodeListResponse(
  episodes: (json['episodes'] as List<dynamic>)
      .map((e) => PodcastEpisodeModel.fromJson(e as Map<String, dynamic>))
      .toList(),
  total: (json['total'] as num).toInt(),
  page: (json['page'] as num).toInt(),
  size: (json['size'] as num).toInt(),
  pages: (json['pages'] as num).toInt(),
  subscriptionId: (json['subscription_id'] as num).toInt(),
);

Map<String, dynamic> _$PodcastEpisodeListResponseToJson(
  PodcastEpisodeListResponse instance,
) => <String, dynamic>{
  'episodes': instance.episodes,
  'total': instance.total,
  'page': instance.page,
  'size': instance.size,
  'pages': instance.pages,
  'subscription_id': instance.subscriptionId,
};

PodcastEpisodeDetailResponse _$PodcastEpisodeDetailResponseFromJson(
  Map<String, dynamic> json,
) => PodcastEpisodeDetailResponse(
  episode: PodcastEpisodeModel.fromJson(
    json['episode'] as Map<String, dynamic>,
  ),
  subscription: json['subscription'] as Map<String, dynamic>?,
  relatedEpisodes: (json['relatedEpisodes'] as List<dynamic>?)
      ?.map((e) => e as Map<String, dynamic>)
      .toList(),
);

Map<String, dynamic> _$PodcastEpisodeDetailResponseToJson(
  PodcastEpisodeDetailResponse instance,
) => <String, dynamic>{
  'episode': instance.episode,
  'subscription': instance.subscription,
  'relatedEpisodes': instance.relatedEpisodes,
};

PodcastFeedResponse _$PodcastFeedResponseFromJson(Map<String, dynamic> json) =>
    PodcastFeedResponse(
      items: (json['items'] as List<dynamic>)
          .map((e) => PodcastEpisodeModel.fromJson(e as Map<String, dynamic>))
          .toList(),
      hasMore: json['hasMore'] as bool? ?? false,
      nextPage: (json['nextPage'] as num?)?.toInt(),
      total: (json['total'] as num).toInt(),
    );

Map<String, dynamic> _$PodcastFeedResponseToJson(
  PodcastFeedResponse instance,
) => <String, dynamic>{
  'items': instance.items,
  'hasMore': instance.hasMore,
  'nextPage': instance.nextPage,
  'total': instance.total,
};
