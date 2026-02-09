import 'package:dio/dio.dart';
import 'package:retrofit/retrofit.dart';

import '../models/podcast_episode_model.dart';
import '../models/podcast_playback_model.dart';
import '../models/podcast_queue_model.dart';
import '../models/podcast_subscription_model.dart';
import '../models/schedule_config_model.dart';
import '../models/podcast_transcription_model.dart';
import '../models/podcast_conversation_model.dart';

part 'podcast_api_service.g.dart';

@RestApi()
abstract class PodcastApiService {
  factory PodcastApiService(Dio dio, {String baseUrl}) = _PodcastApiService;

  // === Subscription Management ===

  @POST('/subscriptions/podcasts')
  Future<PodcastSubscriptionModel> addSubscription(
    @Body() PodcastSubscriptionCreateRequest request,
  );

  @POST('/subscriptions/podcasts/bulk')
  Future<dynamic> addSubscriptionsBatch(
    @Body() List<PodcastSubscriptionCreateRequest> request,
  );

  @GET('/subscriptions/podcasts')
  Future<PodcastSubscriptionListResponse> listSubscriptions(
    @Query('page') int page,
    @Query('size') int size,
    @Query('category_id') int? categoryId,
    @Query('status') String? status,
  );

  @GET('/subscriptions/podcasts/{subscriptionId}')
  Future<PodcastSubscriptionModel> getSubscription(
    @Path('subscriptionId') int subscriptionId,
  );

  @DELETE('/subscriptions/podcasts/{subscriptionId}')
  Future<void> deleteSubscription(@Path('subscriptionId') int subscriptionId);

  @POST('/subscriptions/podcasts/bulk-delete')
  Future<PodcastSubscriptionBulkDeleteResponse> bulkDeleteSubscriptions(
    @Body() PodcastSubscriptionBulkDeleteRequest request,
  );

  @POST('/subscriptions/podcasts/{subscriptionId}/refresh')
  Future<void> refreshSubscription(@Path('subscriptionId') int subscriptionId);

  @POST('/subscriptions/podcasts/{subscriptionId}/reparse')
  Future<ReparseResponse> reparseSubscription(
    @Path('subscriptionId') int subscriptionId,
    @Query('force_all') bool forceAll,
  );

  @GET('/subscriptions/podcasts/{subscriptionId}/schedule')
  Future<ScheduleConfigResponse> getSubscriptionSchedule(
    @Path('subscriptionId') int subscriptionId,
  );

  @PATCH('/subscriptions/podcasts/{subscriptionId}/schedule')
  Future<ScheduleConfigResponse> updateSubscriptionSchedule(
    @Path('subscriptionId') int subscriptionId,
    @Body() ScheduleConfigUpdateRequest request,
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

  // === Queue Management ===

  @GET('/podcasts/queue')
  Future<PodcastQueueModel> getQueue();

  @POST('/podcasts/queue/items')
  Future<PodcastQueueModel> addQueueItem(
    @Body() PodcastQueueAddItemRequest request,
  );

  @DELETE('/podcasts/queue/items/{episodeId}')
  Future<PodcastQueueModel> removeQueueItem(@Path('episodeId') int episodeId);

  @PUT('/podcasts/queue/items/reorder')
  Future<PodcastQueueModel> reorderQueueItems(
    @Body() PodcastQueueReorderRequest request,
  );

  @POST('/podcasts/queue/current')
  Future<PodcastQueueModel> setQueueCurrent(
    @Body() PodcastQueueSetCurrentRequest request,
  );

  @POST('/podcasts/queue/current/complete')
  Future<PodcastQueueModel> completeQueueCurrent(
    @Body() Map<String, dynamic> request,
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
  Future<SimpleResponse> getRecommendations(@Query('limit') int limit);

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
  Future<void> deleteTranscription(@Path('episodeId') int episodeId);

  @GET('/podcasts/episodes/{episodeId}/transcription/status')
  Future<PodcastTranscriptionResponse> getTranscriptionStatus(
    @Path('episodeId') int episodeId,
  );

  // === Conversation Management ===

  @GET('/podcasts/episodes/{episodeId}/conversations')
  Future<PodcastConversationHistoryResponse> getConversationHistory(
    @Path('episodeId') int episodeId,
    @Query('limit') int limit,
  );

  @POST('/podcasts/episodes/{episodeId}/conversations')
  Future<PodcastConversationSendResponse> sendConversationMessage(
    @Path('episodeId') int episodeId,
    @Body() PodcastConversationSendRequest request,
  );

  @DELETE('/podcasts/episodes/{episodeId}/conversations')
  Future<PodcastConversationClearResponse> clearConversationHistory(
    @Path('episodeId') int episodeId,
  );

  @GET('/subscriptions/podcasts/schedule/all')
  Future<List<ScheduleConfigResponse>> getAllSubscriptionSchedules();

  @POST('/subscriptions/podcasts/schedule/batch-update')
  Future<List<ScheduleConfigResponse>> batchUpdateSubscriptionSchedules(
    @Body() Map<String, dynamic> requestData,
  );
}
