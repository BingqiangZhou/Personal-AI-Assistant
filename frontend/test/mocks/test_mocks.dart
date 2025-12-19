import 'package:mockito/annotations.dart';
import 'package:mockito/mockito.dart';

import 'package:personal_ai_assistant/features/podcast/data/repositories/podcast_repository.dart';
import 'package:personal_ai_assistant/features/podcast/data/services/podcast_api_service.dart';

@GenerateMocks([
  PodcastRepository,
  PodcastApiService,
])
void main() {}