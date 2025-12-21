import '../api/knowledge_api_service.dart';
import '../models/knowledge_model.dart';

class KnowledgeRepository {
  final KnowledgeApiService _apiService;

  KnowledgeRepository(this._apiService);

  Future<List<KnowledgeBaseModel>> getKnowledgeBases({int page = 1, int size = 20}) async {
    final data = await _apiService.listKnowledgeBases(page: page, size: size);
    final List items = data['items'] ?? [];
    return items.map((e) => KnowledgeBaseModel.fromJson(e)).toList();
  }

  Future<KnowledgeBaseModel> createKnowledgeBase({
    required String name,
    String? description,
    bool isPublic = false,
  }) async {
    return _apiService.createKnowledgeBase({
      'name': name,
      'description': description,
      'is_public': isPublic,
    });
  }

  Future<List<DocumentModel>> getDocuments(int kbId, {int page = 1, int size = 20, String? search}) async {
    final data = await _apiService.listDocuments(kbId, page: page, size: size, search: search);
    final List items = data['items'] ?? [];
    return items.map((e) => DocumentModel.fromJson(e)).toList();
  }

  Future<DocumentModel> createDocument({
    required int kbId,
    required String title,
    required String content,
    required String contentType,
    List<String>? tags,
  }) async {
    return _apiService.createDocument(kbId, {
      'title': title,
      'content': content,
      'content_type': contentType,
      'tags': tags,
    });
  }

  Future<void> deleteDocument(int id) => _apiService.deleteDocument(id);
  
  Future<DocumentModel> uploadDocument(int kbId, List<int> bytes, String filename) {
    return _apiService.uploadDocument(kbId, bytes, filename);
  }
  
  Future<List<DocumentModel>> searchAll(String query) => _apiService.searchKnowledge(query);
}
