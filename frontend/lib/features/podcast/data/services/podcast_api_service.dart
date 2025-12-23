import 'package:dio/dio.dart';
import 'package:retrofit/retrofit.dart';

import '../models/podcast_episode_model.dart';
import '../models/podcast_playback_model.dart';
import '../models/podcast_subscription_model.dart';
import '../models/podcast_transcription_model.dart';

part 'podcast_api_service.g.dart';

@RestApi()
abstract class PodcastApiService {
  factory PodcastApiService(Dio dio, {String baseUrl}) = _PodcastApiService;

  // === Subscription Management ===

  @POST('/podcasts/subscriptions')
  Future<PodcastSubscriptionModel> addSubscription(
    @Body() PodcastSubscriptionCreateRequest request,
  );

  @GET('/podcasts/subscriptions')
  Future<PodcastSubscriptionListResponse> listSubscriptions(
    @Query('page') int page,
    @Query('size') int size,
    @Query('category_id') int? categoryId,
    @Query('status') String? status,
  );

  @GET('/podcasts/subscriptions/{subscriptionId}')
  Future<PodcastSubscriptionModel> getSubscription(
    @Path('subscriptionId') int subscriptionId,
  );

  @DELETE('/podcasts/subscriptions/{subscriptionId}')
  Future<void> deleteSubscription(
    @Path('subscriptionId') int subscriptionId,
  );

  @POST('/podcasts/subscriptions/{subscriptionId}/refresh')
  Future<void> refreshSubscription(
    @Path('subscriptionId') int subscriptionId,
  );

  @POST('/podcasts/subscriptions/{subscriptionId}/reparse')
  Future<ReparseResponse> reparseSubscription(
    @Path('subscriptionId') int subscriptionId,
    @Query('force_all') bool forceAll,
  );

  // === Episode Management ===

  @GET('/podcasts/episodes/feed')
  Future<PodcastFeedResponse> getPodcastFeed(
    @Query('page') int page,
    @Query('page_size') int pageSize,
  );

  @GET('/podcasts/episodes')
  Future<PodcastEpisodeListResponse> listEpisodes(
    @Query('subscription_id') int? subscriptionId,
    @Query('page') int page,
    @Query('size') int size,
    @Query('has_summary') bool? hasSummary,
    @Query('is_played') bool? isPlayed,
  );

  @GET('/podcasts/episodes/{episodeId}')
  Future<PodcastEpisodeDetailResponse> getEpisode(
    @Path('episodeId') int episodeId,
  );

  // === Playback Management ===

  @PUT('/podcasts/episodes/{episodeId}/playback')
  Future<PodcastPlaybackStateResponse> updatePlaybackProgress(
    @Path('episodeId') int episodeId,
    @Body() PodcastPlaybackUpdateRequest request,
  );

  @GET('/podcasts/episodes/{episodeId}/playback')
  Future<PodcastPlaybackStateResponse> getPlaybackState(
    @Path('episodeId') int episodeId,
  );

  // === Summary Management ===

  @POST('/podcasts/episodes/{episodeId}/summary')
  Future<PodcastSummaryResponse> generateSummary(
    @Path('episodeId') int episodeId,
    @Body() PodcastSummaryRequest request,
  );

  @GET('/podcasts/summaries/models')
  Future<SummaryModelsResponse> getSummaryModels();

  @GET('/podcasts/summaries/pending')
  Future<SimpleResponse> getPendingSummaries();

  // === Search ===

  @GET('/podcasts/search')
  Future<PodcastEpisodeListResponse> searchPodcasts(
    @Query('q') String query,
    @Query('search_in') String? searchIn,
    @Query('page') int page,
    @Query('size') int size,
  );

  // === Statistics ===

  @GET('/podcasts/stats')
  Future<PodcastStatsResponse> getStats();

  // === Recommendations ===

  @GET('/podcasts/recommendations')
  Future<SimpleResponse> getRecommendations(
    @Query('limit') int limit,
  );

  // === Transcription Management ===

  @GET('/podcasts/episodes/{episodeId}/transcription')
  Future<PodcastTranscriptionResponse> getTranscription(
    @Path('episodeId') int episodeId,
  );

  @POST('/podcasts/episodes/{episodeId}/transcribe')
  Future<PodcastTranscriptionResponse> startTranscription(
    @Path('episodeId') int episodeId,
    @Body() PodcastTranscriptionRequest request,
  );

  @DELETE('/podcasts/episodes/{episodeId}/transcription')
  Future<void> deleteTranscription(
    @Path('episodeId') int episodeId,
  );

  @GET('/podcasts/episodes/{episodeId}/transcription/status')
  Future<PodcastTranscriptionResponse> getTranscriptionStatus(
    @Path('episodeId') int episodeId,
  );
}