import '../../models/ai_model_config_model.dart';
import '../services/ai_model_api_service.dart';

class AIModelRepository {
  final AIModelApiService _apiService;

  AIModelRepository(this._apiService);

  /// 创建模型配置
  Future<AIModelConfigModel> createModel(Map<String, dynamic> modelData) async {
    final response = await _apiService.createModel(modelData);
    return response;
  }

  /// 获取模型列表
  Future<AIModelConfigListResponse> getModels({
    String? modelType,
    bool? isActive,
    String? provider,
    int page = 1,
    int size = 20,
    String? search,
  }) async {
    final response = await _apiService.getModels(
      modelType: modelType,
      isActive: isActive,
      provider: provider,
      page: page,
      size: size,
      search: search,
    );
    return response;
  }

  /// 获取模型详情
  Future<AIModelConfigModel> getModel(int modelId, {bool? decryptKey}) async {
    final response = await _apiService.getModel(modelId, decryptKey: decryptKey);
    return response;
  }

  /// 更新模型配置
  Future<AIModelConfigModel> updateModel(
    int modelId,
    Map<String, dynamic> updateData,
  ) async {
    final response = await _apiService.updateModel(modelId, updateData);
    return response;
  }

  /// 删除模型配置
  Future<void> deleteModel(int modelId) async {
    await _apiService.deleteModel(modelId);
  }

  /// 设置默认模型
  Future<AIModelConfigModel> setDefaultModel(
    int modelId,
    String modelType,
  ) async {
    final response = await _apiService.setDefaultModel(modelId, modelType);
    return response;
  }

  /// 获取默认模型
  Future<AIModelConfigModel> getDefaultModel(String modelType) async {
    final response = await _apiService.getDefaultModel(modelType);
    return response;
  }

  /// 获取活跃模型列表
  Future<List<AIModelConfigModel>> getActiveModels(String modelType) async {
    final response = await _apiService.getActiveModels(modelType);
    return response;
  }

  /// 测试模型连接
  Future<ModelTestResponse> testModel(
    int modelId, {
    Map<String, dynamic>? testData,
  }) async {
    final request = ModelTestRequest(
      modelId: modelId,
      testData: testData ?? {},
    );
    final response = await _apiService.testModel(modelId, request);
    return response;
  }

  /// 获取模型使用统计
  Future<ModelUsageStats> getModelStats(int modelId) async {
    final response = await _apiService.getModelStats(modelId);
    return response;
  }

  /// 获取模型类型使用统计
  Future<List<ModelUsageStats>> getTypeStats(
    String modelType, [
    int? limit,
  ]) async {
    final response = await _apiService.getTypeStats(modelType, limit);
    return response;
  }

  /// 初始化默认模型配置
  Future<List<AIModelConfigModel>> initDefaultModels() async {
    final response = await _apiService.initDefaultModels();
    return response;
  }

  /// 验证API密钥
  Future<APIKeyValidationResponse> validateAPIKey(
    String apiUrl,
    String apiKey,
    String? modelId,
    AIModelType modelType,
  ) async {
    final request = APIKeyValidationRequest(
      apiUrl: apiUrl,
      apiKey: apiKey,
      modelId: modelId,
      modelType: modelType,
    );
    final response = await _apiService.validateAPIKey(request);
    return response;
  }

  /// 批量操作：删除多个模型
  Future<List<bool>> deleteModels(List<int> modelIds) async {
    final results = <bool>[];
    for (final modelId in modelIds) {
      try {
        await deleteModel(modelId);
        results.add(true);
      } catch (e) {
        results.add(false);
      }
    }
    return results;
  }

  /// 批量操作：更新多个模型的状态
  Future<List<bool>> updateModelsStatus(
    List<int> modelIds,
    bool isActive,
  ) async {
    final results = <bool>[];
    for (final modelId in modelIds) {
      try {
        await updateModel(modelId, {'is_active': isActive});
        results.add(true);
      } catch (e) {
        results.add(false);
      }
    }
    return results;
  }

  /// 导出模型配置
  Future<Map<String, dynamic>> exportModels({
    List<int>? modelIds,
    bool includeApiKey = false,
  }) async {
    final List<AIModelConfigModel> models;

    if (modelIds != null) {
      models = [];
      for (final modelId in modelIds) {
        final model = await getModel(modelId);
        models.add(model);
      }
    } else {
      final response = await getModels();
      models = response.models;
    }

    final exportedModels = models.map((model) {
      final modelJson = model.toJson();
      if (!includeApiKey) {
        modelJson.remove('apiKey');
      }
      return modelJson;
    }).toList();

    return {
      'models': exportedModels,
      'export_time': DateTime.now().toIso8601String(),
      'version': '1.0',
      'include_api_key': includeApiKey,
    };
  }

  /// 搜索模型
  Future<AIModelConfigListResponse> searchModels(
    String query, {
    String? modelType,
    int page = 1,
    int size = 20,
  }) async {
    return getModels(
      search: query,
      modelType: modelType,
      page: page,
      size: size,
    );
  }

  /// 获取模型使用趋势（最近N天）
  Future<Map<String, dynamic>> getModelUsageTrend(
    int modelId,
    int days,
  ) async {
    // 这里可以扩展API来获取更详细的统计数据
    final stats = await getModelStats(modelId);

    // 模拟趋势数据（实际应该从后端获取）
    final List<Map<String, dynamic>> trendData = [];
    final now = DateTime.now();

    for (int i = days - 1; i >= 0; i--) {
      final date = now.subtract(Duration(days: i));
      trendData.add({
        'date': date.toIso8601String().split('T')[0],
        'usage_count': i == 0 ? stats.usageCount : (stats.usageCount * 0.8 / days).round(),
        'success_count': i == 0 ? stats.successCount : (stats.successCount * 0.8 / days).round(),
        'error_count': i == 0 ? stats.errorCount : (stats.errorCount * 0.8 / days).round(),
      });
    }

    return {
      'model_id': modelId,
      'period_days': days,
      'trend_data': trendData,
      'total_usage': stats.usageCount,
      'total_success': stats.successCount,
      'total_error': stats.errorCount,
    };
  }
}