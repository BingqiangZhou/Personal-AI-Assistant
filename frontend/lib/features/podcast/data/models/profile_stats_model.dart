import 'package:equatable/equatable.dart';

class ProfileStatsModel extends Equatable {
  final int totalSubscriptions;
  final int totalEpisodes;
  final int summariesGenerated;
  final int pendingSummaries;
  final int playedEpisodes;

  const ProfileStatsModel({
    required this.totalSubscriptions,
    required this.totalEpisodes,
    required this.summariesGenerated,
    required this.pendingSummaries,
    required this.playedEpisodes,
  });

  factory ProfileStatsModel.fromJson(Map<String, dynamic> json) {
    return ProfileStatsModel(
      totalSubscriptions: (json['total_subscriptions'] as num?)?.toInt() ?? 0,
      totalEpisodes: (json['total_episodes'] as num?)?.toInt() ?? 0,
      summariesGenerated: (json['summaries_generated'] as num?)?.toInt() ?? 0,
      pendingSummaries: (json['pending_summaries'] as num?)?.toInt() ?? 0,
      playedEpisodes: (json['played_episodes'] as num?)?.toInt() ?? 0,
    );
  }

  @override
  List<Object?> get props => [
    totalSubscriptions,
    totalEpisodes,
    summariesGenerated,
    pendingSummaries,
    playedEpisodes,
  ];
}
