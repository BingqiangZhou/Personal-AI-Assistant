import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:personal_ai_assistant/core/providers/core_providers.dart';
import 'package:personal_ai_assistant/features/podcast/data/repositories/podcast_repository.dart';
import 'package:personal_ai_assistant/features/podcast/data/services/podcast_api_service.dart';

final podcastApiServiceProvider = Provider<PodcastApiService>((ref) {
  final dio = ref.read(dioClientProvider).dio;
  return PodcastApiService(dio);
});

final podcastRepositoryProvider = Provider<PodcastRepository>((ref) {
  final apiService = ref.read(podcastApiServiceProvider);
  return PodcastRepository(apiService);
});
