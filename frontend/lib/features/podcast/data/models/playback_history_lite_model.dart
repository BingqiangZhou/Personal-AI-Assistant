import 'package:equatable/equatable.dart';

class PlaybackHistoryLiteItem extends Equatable {
  final int id;
  final int subscriptionId;
  final String? subscriptionTitle;
  final String? subscriptionImageUrl;
  final String title;
  final String? imageUrl;
  final int? audioDuration;
  final int? playbackPosition;
  final DateTime? lastPlayedAt;
  final DateTime publishedAt;

  const PlaybackHistoryLiteItem({
    required this.id,
    required this.subscriptionId,
    this.subscriptionTitle,
    this.subscriptionImageUrl,
    required this.title,
    this.imageUrl,
    this.audioDuration,
    this.playbackPosition,
    this.lastPlayedAt,
    required this.publishedAt,
  });

  factory PlaybackHistoryLiteItem.fromJson(Map<String, dynamic> json) {
    return PlaybackHistoryLiteItem(
      id: (json['id'] as num).toInt(),
      subscriptionId: (json['subscription_id'] as num?)?.toInt() ?? 0,
      subscriptionTitle: json['subscription_title'] as String?,
      subscriptionImageUrl: json['subscription_image_url'] as String?,
      title: json['title'] as String? ?? '',
      imageUrl: json['image_url'] as String?,
      audioDuration: (json['audio_duration'] as num?)?.toInt(),
      playbackPosition: (json['playback_position'] as num?)?.toInt(),
      lastPlayedAt: json['last_played_at'] != null
          ? DateTime.tryParse(json['last_played_at'] as String)
          : null,
      publishedAt:
          DateTime.tryParse(json['published_at'] as String) ?? DateTime(1970),
    );
  }

  String get formattedDuration {
    if (audioDuration == null) return '--:--';
    final duration = Duration(seconds: audioDuration!);
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
    id,
    subscriptionId,
    subscriptionTitle,
    subscriptionImageUrl,
    title,
    imageUrl,
    audioDuration,
    playbackPosition,
    lastPlayedAt,
    publishedAt,
  ];
}

class PlaybackHistoryLiteResponse extends Equatable {
  final List<PlaybackHistoryLiteItem> episodes;
  final int total;
  final int page;
  final int size;
  final int pages;

  const PlaybackHistoryLiteResponse({
    required this.episodes,
    required this.total,
    required this.page,
    required this.size,
    required this.pages,
  });

  factory PlaybackHistoryLiteResponse.fromJson(Map<String, dynamic> json) {
    final episodesJson = json['episodes'] as List<dynamic>? ?? const [];
    return PlaybackHistoryLiteResponse(
      episodes: episodesJson
          .map(
            (item) =>
                PlaybackHistoryLiteItem.fromJson(item as Map<String, dynamic>),
          )
          .toList(),
      total: (json['total'] as num?)?.toInt() ?? 0,
      page: (json['page'] as num?)?.toInt() ?? 1,
      size: (json['size'] as num?)?.toInt() ?? 20,
      pages: (json['pages'] as num?)?.toInt() ?? 0,
    );
  }

  @override
  List<Object?> get props => [episodes, total, page, size, pages];
}
