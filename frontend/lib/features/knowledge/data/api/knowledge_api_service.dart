import 'package:dio/dio.dart';
import '../models/knowledge_model.dart';

class KnowledgeApiService {
  final Dio _dio;

  KnowledgeApiService(this._dio);

  // Knowledge Bases
  Future<Map<String, dynamic>> listKnowledgeBases({int page = 1, int size = 20}) async {
    final response = await _dio.get('/knowledge/bases/', queryParameters: {
      'page': page,
      'size': size,
    });
    return response.data;
  }

  Future<KnowledgeBaseModel> createKnowledgeBase(Map<String, dynamic> data) async {
    final response = await _dio.post('/knowledge/bases/', data: data);
    return KnowledgeBaseModel.fromJson(response.data);
  }

  Future<KnowledgeBaseModel> getKnowledgeBase(int id) async {
    final response = await _dio.get('/knowledge/bases/$id');
    return KnowledgeBaseModel.fromJson(response.data);
  }

  Future<KnowledgeBaseModel> updateKnowledgeBase(int id, Map<String, dynamic> data) async {
    final response = await _dio.put('/knowledge/bases/$id', data: data);
    return KnowledgeBaseModel.fromJson(response.data);
  }

  Future<void> deleteKnowledgeBase(int id) async {
    await _dio.delete('/knowledge/bases/$id');
  }

  // Documents
  Future<Map<String, dynamic>> listDocuments(int kbId, {int page = 1, int size = 20, String? search}) async {
    final response = await _dio.get('/knowledge/bases/$kbId/documents/', queryParameters: {
      'page': page,
      'size': size,
      if (search != null) 'search': search,
    });
    return response.data;
  }

  Future<DocumentModel> createDocument(int kbId, Map<String, dynamic> data) async {
    final response = await _dio.post('/knowledge/bases/$kbId/documents/', data: {
      ...data,
      'knowledge_base_id': kbId,
    });
    return DocumentModel.fromJson(response.data);
  }

  Future<DocumentModel> getDocument(int id) async {
    final response = await _dio.get('/knowledge/documents/$id');
    return DocumentModel.fromJson(response.data);
  }

  Future<DocumentModel> updateDocument(int id, Map<String, dynamic> data) async {
    final response = await _dio.put('/knowledge/documents/$id', data: data);
    return DocumentModel.fromJson(response.data);
  }

  Future<void> deleteDocument(int id) async {
    await _dio.delete('/knowledge/documents/$id');
  }

  Future<DocumentModel> uploadDocument(int kbId, List<int> bytes, String filename) async {
    final formData = FormData.fromMap({
      'file': MultipartFile.fromBytes(bytes, filename: filename),
    });
    final response = await _dio.post(
      '/knowledge/bases/$kbId/documents/upload',
      data: formData,
    );
    return DocumentModel.fromJson(response.data);
  }

  Future<List<DocumentModel>> searchKnowledge(String query, {List<int>? kbIds}) async {
    final response = await _dio.post('/knowledge/search', data: {
      'query': query,
      if (kbIds != null) 'kb_ids': kbIds,
    });
    return (response.data as List).map((e) => DocumentModel.fromJson(e)).toList();
  }
}
