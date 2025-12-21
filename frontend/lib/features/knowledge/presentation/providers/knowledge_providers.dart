import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../../core/providers/core_providers.dart';
import '../../data/api/knowledge_api_service.dart';
import '../../data/repositories/knowledge_repository.dart';
import '../../data/models/knowledge_model.dart';

// API Service & Repository Providers
final knowledgeApiServiceProvider = Provider<KnowledgeApiService>((ref) {
  final dio = ref.watch(dioClientProvider).dio;
  return KnowledgeApiService(dio);
});

final knowledgeRepositoryProvider = Provider<KnowledgeRepository>((ref) {
  final apiService = ref.watch(knowledgeApiServiceProvider);
  return KnowledgeRepository(apiService);
});

// Knowledge Bases Notifier
class KnowledgeBasesNotifier extends AsyncNotifier<List<KnowledgeBaseModel>> {
  @override
  Future<List<KnowledgeBaseModel>> build() async {
    return ref.watch(knowledgeRepositoryProvider).getKnowledgeBases();
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() => 
      ref.read(knowledgeRepositoryProvider).getKnowledgeBases()
    );
  }

  Future<void> addKnowledgeBase({
    required String name,
    String? description,
  }) async {
    await ref.read(knowledgeRepositoryProvider).createKnowledgeBase(
      name: name,
      description: description,
    );
    await refresh();
  }
}

final knowledgeBasesProvider = AsyncNotifierProvider<KnowledgeBasesNotifier, List<KnowledgeBaseModel>>(
  () => KnowledgeBasesNotifier(),
);

// Documents Notifier
class DocumentsNotifier extends AsyncNotifier<List<DocumentModel>> {
  final int kbId;
  
  DocumentsNotifier(this.kbId);

  @override
  Future<List<DocumentModel>> build() async {
    return ref.watch(knowledgeRepositoryProvider).getDocuments(kbId);
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() => 
      ref.read(knowledgeRepositoryProvider).getDocuments(kbId)
    );
  }

  Future<void> addDocument({
    required String title,
    required String content,
    String contentType = 'markdown',
  }) async {
    await ref.read(knowledgeRepositoryProvider).createDocument(
      kbId: kbId,
      title: title,
      content: content,
      contentType: contentType,
    );
    await refresh();
  }

  Future<void> uploadDocument(List<int> bytes, String filename) async {
    await ref.read(knowledgeRepositoryProvider).uploadDocument(kbId, bytes, filename);
    await refresh();
  }
}

final _documentsProviders = <int, AsyncNotifierProvider<DocumentsNotifier, List<DocumentModel>>>{};

AsyncNotifierProvider<DocumentsNotifier, List<DocumentModel>> documentsProvider(int kbId) {
  return _documentsProviders.putIfAbsent(
    kbId,
    () => AsyncNotifierProvider<DocumentsNotifier, List<DocumentModel>>(() => DocumentsNotifier(kbId)),
  );
}

final searchDocumentsProvider = FutureProvider.family<List<DocumentModel>, String>((ref, query) async {
  if (query.isEmpty) return [];
  return ref.watch(knowledgeRepositoryProvider).searchAll(query);
});
