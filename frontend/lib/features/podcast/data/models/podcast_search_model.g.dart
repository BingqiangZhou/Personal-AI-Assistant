// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'podcast_search_model.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

PodcastSearchResult _$PodcastSearchResultFromJson(Map<String, dynamic> json) =>
    PodcastSearchResult(
      collectionId: (json['collectionId'] as num?)?.toInt(),
      collectionName: json['collectionName'] as String?,
      artistName: json['artistName'] as String?,
      artworkUrl100: json['artworkUrl100'] as String?,
      artworkUrl600: json['artworkUrl600'] as String?,
      feedUrl: json['feedUrl'] as String?,
      collectionViewUrl: json['collectionViewUrl'] as String?,
      primaryGenreName: json['primaryGenreName'] as String?,
      trackCount: (json['trackCount'] as num?)?.toInt(),
      releaseDate: json['releaseDate'] as String?,
    );

Map<String, dynamic> _$PodcastSearchResultToJson(
  PodcastSearchResult instance,
) => <String, dynamic>{
  'collectionId': instance.collectionId,
  'collectionName': instance.collectionName,
  'artistName': instance.artistName,
  'artworkUrl100': instance.artworkUrl100,
  'artworkUrl600': instance.artworkUrl600,
  'feedUrl': instance.feedUrl,
  'collectionViewUrl': instance.collectionViewUrl,
  'primaryGenreName': instance.primaryGenreName,
  'trackCount': instance.trackCount,
  'releaseDate': instance.releaseDate,
};

iTunesSearchResponse _$iTunesSearchResponseFromJson(
  Map<String, dynamic> json,
) => iTunesSearchResponse(
  resultCount: (json['resultCount'] as num).toInt(),
  results: (json['results'] as List<dynamic>)
      .map((e) => PodcastSearchResult.fromJson(e as Map<String, dynamic>))
      .toList(),
);

Map<String, dynamic> _$iTunesSearchResponseToJson(
  iTunesSearchResponse instance,
) => <String, dynamic>{
  'resultCount': instance.resultCount,
  'results': instance.results,
};
