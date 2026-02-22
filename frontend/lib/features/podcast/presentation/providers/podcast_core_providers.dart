import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/providers/core_providers.dart';
import '../../data/repositories/podcast_repository.dart';
import '../../data/services/podcast_api_service.dart';

final podcastApiServiceProvider = Provider<PodcastApiService>((ref) {
  final dio = ref.watch(dioClientProvider).dio;
  return PodcastApiService(dio);
});

final podcastRepositoryProvider = Provider<PodcastRepository>((ref) {
  final apiService = ref.watch(podcastApiServiceProvider);
  return PodcastRepository(apiService);
});
