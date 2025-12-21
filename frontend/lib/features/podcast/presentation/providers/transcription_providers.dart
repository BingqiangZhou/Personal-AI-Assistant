import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../data/models/podcast_transcription_model.dart';
import 'podcast_providers.dart';

// Transcription state provider for each episode
final transcriptionStateProviders = <int, AsyncNotifierProvider<TranscriptionNotifier, PodcastTranscriptionResponse?>>{};

/// Get or create a transcription state provider for a specific episode
AsyncNotifierProvider<TranscriptionNotifier, PodcastTranscriptionResponse?> getTranscriptionProvider(int episodeId) {
  return transcriptionStateProviders.putIfAbsent(
    episodeId,
    () => AsyncNotifierProvider<TranscriptionNotifier, PodcastTranscriptionResponse?>(() => TranscriptionNotifier(episodeId)),
  );
}

/// Notifier for managing transcription state
class TranscriptionNotifier extends AsyncNotifier<PodcastTranscriptionResponse?> {
  final int episodeId;

  TranscriptionNotifier(this.episodeId);

  @override
  Future<PodcastTranscriptionResponse?> build() async {
    return null;
  }

  /// Load transcription for the episode
  Future<void> loadTranscription() async {
    state = const AsyncValue.loading();

    try {
      final repository = ref.read(podcastRepositoryProvider);
      final transcription = await repository.getTranscription(episodeId);
      state = AsyncValue.data(transcription);
    } catch (error, stackTrace) {
      state = AsyncValue.error(error, stackTrace);
    }
  }

  /// Start transcription for the episode
  Future<void> startTranscription() async {
    state = const AsyncValue.loading();

    try {
      final repository = ref.read(podcastRepositoryProvider);
      final transcription = await repository.startTranscription(episodeId);
      state = AsyncValue.data(transcription);
    } catch (error, stackTrace) {
      state = AsyncValue.error(error, stackTrace);
    }
  }

  /// Refresh transcription status
  Future<void> refreshStatus() async {
    if (state.value == null) {
      await loadTranscription();
      return;
    }

    try {
      final repository = ref.read(podcastRepositoryProvider);
      final transcription = await repository.getTranscriptionStatus(episodeId);
      state = AsyncValue.data(transcription);
    } catch (error, stackTrace) {
      state = AsyncValue.error(error, stackTrace);
    }
  }

  /// Delete transcription
  Future<void> deleteTranscription() async {
    try {
      final repository = ref.read(podcastRepositoryProvider);
      await repository.deleteTranscription(episodeId);
      state = const AsyncValue.data(null);
    } catch (error, stackTrace) {
      state = AsyncValue.error(error, stackTrace);
    }
  }

  /// Reset state
  void reset() {
    state = const AsyncValue.data(null);
  }
}

// Provider for transcription search query
final transcriptionSearchQueryProvider = NotifierProvider<TranscriptionSearchQueryNotifier, String>(TranscriptionSearchQueryNotifier.new);

// Provider for transcription search results
final transcriptionSearchResultsProvider = NotifierProvider<TranscriptionSearchResultsNotifier, List<String>>(TranscriptionSearchResultsNotifier.new);

/// Notifier for managing transcription search query
class TranscriptionSearchQueryNotifier extends Notifier<String> {
  @override
  String build() => '';

  void updateQuery(String query) => state = query;
  void clearQuery() => state = '';
}

/// Notifier for managing transcription search results
class TranscriptionSearchResultsNotifier extends Notifier<List<String>> {
  @override
  List<String> build() => [];

  void setResults(List<String> results) => state = results;
  void clearResults() => state = [];
}

// Helper functions for search
void updateTranscriptionSearchQuery(WidgetRef ref, String query) {
  ref.read(transcriptionSearchQueryProvider.notifier).updateQuery(query);
}

void clearTranscriptionSearchQuery(WidgetRef ref) {
  ref.read(transcriptionSearchQueryProvider.notifier).clearQuery();
  ref.read(transcriptionSearchResultsProvider.notifier).clearResults();
}

void searchTranscript(WidgetRef ref, String content, String query) {
  if (query.isEmpty || content.isEmpty) {
    ref.read(transcriptionSearchResultsProvider.notifier).clearResults();
    return;
  }

  final lines = content.split('\n');
  final results = <String>[];

  for (var i = 0; i < lines.length; i++) {
    final line = lines[i].trim();
    if (line.isNotEmpty && line.toLowerCase().contains(query.toLowerCase())) {
      results.add(line);
    }
  }

  ref.read(transcriptionSearchResultsProvider.notifier).setResults(results);
}

// Helper function to get transcription text content
String? getTranscriptionText(PodcastTranscriptionResponse? transcription) {
  return transcription?.displayContent;
}

// Helper function to check if transcription is processing
bool isTranscriptionProcessing(PodcastTranscriptionResponse? transcription) {
  return transcription?.isProcessing == true;
}

// Helper function to check if transcription is completed
bool isTranscriptionCompleted(PodcastTranscriptionResponse? transcription) {
  return transcription?.isCompleted == true;
}

// Helper function to check if transcription failed
bool isTranscriptionFailed(PodcastTranscriptionResponse? transcription) {
  return transcription?.isFailed == true;
}

// Helper function to get transcription progress
double getTranscriptionProgress(PodcastTranscriptionResponse? transcription) {
  return transcription?.progressPercentage ?? 0.0;
}

// Helper function to get transcription status description
String getTranscriptionStatusDescription(PodcastTranscriptionResponse? transcription) {
  return transcription?.statusDescription ?? '未知状态';
}