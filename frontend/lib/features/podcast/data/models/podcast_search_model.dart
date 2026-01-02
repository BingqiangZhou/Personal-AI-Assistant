import 'package:equatable/equatable.dart';
import 'package:json_annotation/json_annotation.dart';

part 'podcast_search_model.g.dart';

/// 国家/地区枚举
enum PodcastCountry {
  china('cn', '中国'),
  usa('us', '美国');

  final String code;
  final String displayName;

  const PodcastCountry(this.code, this.displayName);
}

/// iTunes 搜索结果模型
@JsonSerializable()
class PodcastSearchResult extends Equatable {
  final int collectionId;
  @JsonKey(name: 'collectionName')
  final String collectionName;
  @JsonKey(name: 'artistName')
  final String artistName;
  @JsonKey(name: 'artworkUrl100')
  final String artworkUrl100;
  @JsonKey(name: 'artworkUrl600')
  final String? artworkUrl600;
  @JsonKey(name: 'feedUrl')
  final String feedUrl;
  @JsonKey(name: 'collectionViewUrl')
  final String? collectionViewUrl;
  @JsonKey(name: 'primaryGenreName')
  final String? primaryGenreName;
  @JsonKey(name: 'trackCount')
  final int trackCount;
  @JsonKey(name: 'releaseDate')
  final String? releaseDate;

  const PodcastSearchResult({
    required this.collectionId,
    required this.collectionName,
    required this.artistName,
    required this.artworkUrl100,
    this.artworkUrl600,
    required this.feedUrl,
    this.collectionViewUrl,
    this.primaryGenreName,
    required this.trackCount,
    this.releaseDate,
  });

  factory PodcastSearchResult.fromJson(Map<String, dynamic> json) =>
      _$PodcastSearchResultFromJson(json);

  Map<String, dynamic> toJson() => _$PodcastSearchResultToJson(this);

  @override
  List<Object?> get props => [
        collectionId,
        collectionName,
        artistName,
        artworkUrl100,
        artworkUrl600,
        feedUrl,
        collectionViewUrl,
        primaryGenreName,
        trackCount,
        releaseDate,
      ];
}

/// iTunes Search API 响应模型
@JsonSerializable()
class iTunesSearchResponse extends Equatable {
  final int resultCount;
  final List<PodcastSearchResult> results;

  const iTunesSearchResponse({
    required this.resultCount,
    required this.results,
  });

  factory iTunesSearchResponse.fromJson(Map<String, dynamic> json) =>
      _$iTunesSearchResponseFromJson(json);

  Map<String, dynamic> toJson() => _$iTunesSearchResponseToJson(this);

  @override
  List<Object?> get props => [resultCount, results];
}
