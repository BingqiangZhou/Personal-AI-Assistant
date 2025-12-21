import 'package:dio/dio.dart';

import '../../../../core/network/exceptions/network_exceptions.dart';
import '../models/podcast_episode_model.dart';
import '../models/podcast_playback_model.dart';
import '../models/podcast_subscription_model.dart';
import '../models/podcast_transcription_model.dart';
import '../services/podcast_api_service.dart';

class PodcastRepository {
  final PodcastApiService _apiService;

  PodcastRepository(this._apiService);

  // === Subscription Management ===

  Future<PodcastSubscriptionModel> addSubscription({
    required String feedUrl,
    List<int>? categoryIds,
  }) async {
    try {
      final request = PodcastSubscriptionCreateRequest(
        feedUrl: feedUrl,
        categoryIds: categoryIds,
      );
      return await _apiService.addSubscription(request);
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  Future<PodcastSubscriptionListResponse> listSubscriptions({
    int page = 1,
    int size = 20,
    int? categoryId,
    String? status,
  }) async {
    try {
      return await _apiService.listSubscriptions(
        page,
        size,
        categoryId,
        status,
      );
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  Future<PodcastSubscriptionModel> getSubscription(int subscriptionId) async {
    try {
      return await _apiService.getSubscription(subscriptionId);
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  Future<void> deleteSubscription(int subscriptionId) async {
    try {
      await _apiService.deleteSubscription(subscriptionId);
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  Future<void> refreshSubscription(int subscriptionId) async {
    try {
      await _apiService.refreshSubscription(subscriptionId);
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  Future<ReparseResponse> reparseSubscription(int subscriptionId, bool forceAll) async {
    try {
      return await _apiService.reparseSubscription(subscriptionId, forceAll);
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  // === Episode Management ===

  Future<PodcastFeedResponse> getPodcastFeed({
    required int page,
    required int pageSize,
  }) async {
    try {
      return await _apiService.getPodcastFeed(page, pageSize);
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  Future<PodcastEpisodeListResponse> listEpisodes({
    int? subscriptionId,
    int page = 1,
    int size = 20,
    bool? hasSummary,
    bool? isPlayed,
  }) async {
    try {
      return await _apiService.listEpisodes(
        subscriptionId,
        page,
        size,
        hasSummary,
        isPlayed,
      );
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  Future<PodcastEpisodeDetailResponse> getEpisode(int episodeId) async {
    try {
      return await _apiService.getEpisode(episodeId);
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  // === Playback Management ===

  Future<PodcastPlaybackStateResponse> updatePlaybackProgress({
    required int episodeId,
    required int position,
    required bool isPlaying,
    double playbackRate = 1.0,
  }) async {
    try {
      final request = PodcastPlaybackUpdateRequest(
        position: position,
        isPlaying: isPlaying,
        playbackRate: playbackRate,
      );
      return await _apiService.updatePlaybackProgress(episodeId, request);
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  Future<PodcastPlaybackStateResponse> getPlaybackState(int episodeId) async {
    try {
      return await _apiService.getPlaybackState(episodeId);
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  // === Summary Management ===

  Future<PodcastSummaryResponse> generateSummary({
    required int episodeId,
    bool forceRegenerate = false,
    bool? useTranscript,
  }) async {
    try {
      final request = PodcastSummaryRequest(
        forceRegenerate: forceRegenerate,
        useTranscript: useTranscript,
      );
      return await _apiService.generateSummary(episodeId, request);
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  Future<void> getPendingSummaries() async {
    try {
      await _apiService.getPendingSummaries();
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  // === Search ===

  Future<PodcastEpisodeListResponse> searchPodcasts({
    required String query,
    String searchIn = 'all',
    int page = 1,
    int size = 20,
  }) async {
    try {
      return await _apiService.searchPodcasts(
        query,
        searchIn,
        page,
        size,
      );
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  // === Statistics ===

  Future<PodcastStatsResponse> getStats() async {
    try {
      return await _apiService.getStats();
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  // === Recommendations ===

  Future<void> getRecommendations({int limit = 10}) async {
    try {
      await _apiService.getRecommendations(limit);
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  // === Transcription Management ===

  Future<PodcastTranscriptionResponse?> getTranscription(int episodeId) async {
    try {
      return await _apiService.getTranscription(episodeId);
    } on DioException catch (e) {
      // If transcription not found (404), return null instead of throwing
      if (e.response?.statusCode == 404) {
        return null;
      }
      throw NetworkException.fromDioError(e);
    }
  }

  Future<PodcastTranscriptionResponse> startTranscription(
    int episodeId, {
    bool forceRegenerate = false,
    int? chunkSizeMb,
    String? transcriptionModel,
  }) async {
    try {
      final request = PodcastTranscriptionRequest(
        forceRegenerate: forceRegenerate,
        chunkSizeMb: chunkSizeMb,
        transcriptionModel: transcriptionModel,
      );
      return await _apiService.startTranscription(episodeId, request);
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  Future<void> deleteTranscription(int episodeId) async {
    try {
      await _apiService.deleteTranscription(episodeId);
    } on DioException catch (e) {
      throw NetworkException.fromDioError(e);
    }
  }

  Future<PodcastTranscriptionResponse?> getTranscriptionStatus(int episodeId) async {
    try {
      return await _apiService.getTranscriptionStatus(episodeId);
    } on DioException catch (e) {
      // If transcription not found (404), return null instead of throwing
      if (e.response?.statusCode == 404) {
        return null;
      }
      throw NetworkException.fromDioError(e);
    }
  }
}