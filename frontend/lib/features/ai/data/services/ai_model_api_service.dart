import 'package:dio/dio.dart';
import 'package:retrofit/retrofit.dart';

import '../../models/ai_model_config_model.dart';

part 'ai_model_api_service.g.dart';

@RestApi()
abstract class AIModelApiService {
  factory AIModelApiService(Dio dio, {String baseUrl}) = _AIModelApiService;

  /// 创建AI模型配置
  @POST('/ai/models')
  Future<AIModelConfigModel> createModel(
    @Body() Map<String, dynamic> modelData,
  );

  /// 获取AI模型配置列表
  @GET('/ai/models')
  Future<AIModelConfigListResponse> getModels({
    @Query('model_type') String? modelType,
    @Query('is_active') bool? isActive,
    @Query('provider') String? provider,
    @Query('page') int? page,
    @Query('size') int? size,
    @Query('search') String? search,
  });

  /// 获取AI模型配置详情
  @GET('/ai/models/{modelId}')
  Future<AIModelConfigModel> getModel(
    @Path() int modelId,
  );

  /// 更新AI模型配置
  @PUT('/ai/models/{modelId}')
  Future<AIModelConfigModel> updateModel(
    @Path() int modelId,
    @Body() Map<String, dynamic> modelData,
  );

  /// 删除AI模型配置
  @DELETE('/ai/models/{modelId}')
  Future<void> deleteModel(
    @Path() int modelId,
  );

  /// 设置默认模型
  @POST('/ai/models/{modelId}/set-default')
  Future<AIModelConfigModel> setDefaultModel(
    @Path() int modelId,
    @Query('model_type') String modelType,
  );

  /// 获取默认模型
  @GET('/ai/models/default/{modelType}')
  Future<AIModelConfigModel> getDefaultModel(
    @Path() String modelType,
  );

  /// 获取活跃模型列表
  @GET('/ai/models/active/{modelType}')
  Future<List<AIModelConfigModel>> getActiveModels(
    @Path() String modelType,
  );

  /// 测试模型连接
  @POST('/ai/models/{modelId}/test')
  Future<ModelTestResponse> testModel(
    @Path() int modelId,
    @Body() ModelTestRequest request,
  );

  /// 获取模型使用统计
  @GET('/ai/models/{modelId}/stats')
  Future<ModelUsageStats> getModelStats(
    @Path() int modelId,
  );

  /// 获取模型类型使用统计
  @GET('/ai/models/stats/{modelType}')
  Future<List<ModelUsageStats>> getTypeStats(
    @Path() String modelType,
    @Query('limit') int? limit,
  );

  /// 初始化默认模型配置
  @POST('/ai/models/init-defaults')
  Future<List<AIModelConfigModel>> initDefaultModels();

  /// 验证API密钥
  @POST('/ai/models/validate-api-key')
  Future<APIKeyValidationResponse> validateAPIKey(
    @Body() APIKeyValidationRequest request,
  );

  /// 获取RSA公钥用于前端加密
  @GET('/ai/security/rsa-public-key')
  Future<Map<String, dynamic>> getRSAPublicKey();
}