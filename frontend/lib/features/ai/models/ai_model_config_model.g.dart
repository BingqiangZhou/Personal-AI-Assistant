// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'ai_model_config_model.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

AIModelConfigModel _$AIModelConfigModelFromJson(Map<String, dynamic> json) =>
    AIModelConfigModel(
      id: (json['id'] as num).toInt(),
      name: json['name'] as String,
      displayName: json['display_name'] as String,
      description: json['description'] as String?,
      modelType: $enumDecode(_$AIModelTypeEnumMap, json['model_type']),
      apiUrl: json['api_url'] as String,
      apiKey: json['api_key'] as String?,
      apiKeyEncrypted: json['api_key_encrypted'] as bool,
      modelId: json['model_id'] as String,
      provider: json['provider'] as String,
      maxTokens: (json['max_tokens'] as num?)?.toInt(),
      temperature: json['temperature'] as String?,
      timeoutSeconds: (json['timeout_seconds'] as num?)?.toInt() ?? 300,
      maxRetries: (json['max_retries'] as num?)?.toInt() ?? 3,
      maxConcurrentRequests:
          (json['max_concurrent_requests'] as num?)?.toInt() ?? 1,
      rateLimitPerMinute:
          (json['rate_limit_per_minute'] as num?)?.toInt() ?? 60,
      costPerInputToken: json['cost_per_input_token'] as String?,
      costPerOutputToken: json['cost_per_output_token'] as String?,
      extraConfig: json['extra_config'] as Map<String, dynamic>?,
      isActive: json['is_active'] as bool? ?? true,
      isDefault: json['is_default'] as bool? ?? false,
      isSystem: json['is_system'] as bool? ?? false,
      usageCount: (json['usage_count'] as num?)?.toInt() ?? 0,
      successCount: (json['success_count'] as num?)?.toInt() ?? 0,
      errorCount: (json['error_count'] as num?)?.toInt() ?? 0,
      totalTokensUsed: (json['total_tokens_used'] as num?)?.toInt() ?? 0,
      successRate: (json['success_rate'] as num?)?.toDouble() ?? 0.0,
      createdAt: DateTime.parse(json['created_at'] as String),
      updatedAt: DateTime.parse(json['updated_at'] as String),
      lastUsedAt: json['last_used_at'] == null
          ? null
          : DateTime.parse(json['last_used_at'] as String),
    );

Map<String, dynamic> _$AIModelConfigModelToJson(AIModelConfigModel instance) =>
    <String, dynamic>{
      'id': instance.id,
      'name': instance.name,
      'display_name': instance.displayName,
      'description': instance.description,
      'model_type': _$AIModelTypeEnumMap[instance.modelType]!,
      'api_url': instance.apiUrl,
      'api_key': instance.apiKey,
      'api_key_encrypted': instance.apiKeyEncrypted,
      'model_id': instance.modelId,
      'provider': instance.provider,
      'max_tokens': instance.maxTokens,
      'temperature': instance.temperature,
      'timeout_seconds': instance.timeoutSeconds,
      'max_retries': instance.maxRetries,
      'max_concurrent_requests': instance.maxConcurrentRequests,
      'rate_limit_per_minute': instance.rateLimitPerMinute,
      'cost_per_input_token': instance.costPerInputToken,
      'cost_per_output_token': instance.costPerOutputToken,
      'extra_config': instance.extraConfig,
      'is_active': instance.isActive,
      'is_default': instance.isDefault,
      'is_system': instance.isSystem,
      'usage_count': instance.usageCount,
      'success_count': instance.successCount,
      'error_count': instance.errorCount,
      'total_tokens_used': instance.totalTokensUsed,
      'success_rate': instance.successRate,
      'created_at': instance.createdAt.toIso8601String(),
      'updated_at': instance.updatedAt.toIso8601String(),
      'last_used_at': instance.lastUsedAt?.toIso8601String(),
    };

const _$AIModelTypeEnumMap = {
  AIModelType.transcription: 'transcription',
  AIModelType.textGeneration: 'text_generation',
};

AIModelConfigListResponse _$AIModelConfigListResponseFromJson(
  Map<String, dynamic> json,
) => AIModelConfigListResponse(
  models: (json['models'] as List<dynamic>)
      .map((e) => AIModelConfigModel.fromJson(e as Map<String, dynamic>))
      .toList(),
  total: (json['total'] as num).toInt(),
  page: (json['page'] as num).toInt(),
  size: (json['size'] as num).toInt(),
  pages: (json['pages'] as num).toInt(),
);

Map<String, dynamic> _$AIModelConfigListResponseToJson(
  AIModelConfigListResponse instance,
) => <String, dynamic>{
  'models': instance.models,
  'total': instance.total,
  'page': instance.page,
  'size': instance.size,
  'pages': instance.pages,
};

ModelUsageStats _$ModelUsageStatsFromJson(Map<String, dynamic> json) =>
    ModelUsageStats(
      modelId: (json['model_id'] as num).toInt(),
      modelName: json['model_name'] as String,
      modelType: json['model_type'] as String,
      usageCount: (json['usage_count'] as num).toInt(),
      successCount: (json['success_count'] as num).toInt(),
      errorCount: (json['error_count'] as num).toInt(),
      successRate: (json['success_rate'] as num).toDouble(),
      totalTokensUsed: (json['total_tokens_used'] as num).toInt(),
      lastUsedAt: json['last_used_at'] == null
          ? null
          : DateTime.parse(json['last_used_at'] as String),
      totalCost: (json['total_cost'] as num?)?.toDouble(),
    );

Map<String, dynamic> _$ModelUsageStatsToJson(ModelUsageStats instance) =>
    <String, dynamic>{
      'model_id': instance.modelId,
      'model_name': instance.modelName,
      'model_type': instance.modelType,
      'usage_count': instance.usageCount,
      'success_count': instance.successCount,
      'error_count': instance.errorCount,
      'success_rate': instance.successRate,
      'total_tokens_used': instance.totalTokensUsed,
      'last_used_at': instance.lastUsedAt?.toIso8601String(),
      'total_cost': instance.totalCost,
    };

ModelTestRequest _$ModelTestRequestFromJson(Map<String, dynamic> json) =>
    ModelTestRequest(
      modelId: (json['model_id'] as num).toInt(),
      testData: json['test_data'] as Map<String, dynamic>? ?? const {},
    );

Map<String, dynamic> _$ModelTestRequestToJson(ModelTestRequest instance) =>
    <String, dynamic>{
      'model_id': instance.modelId,
      'test_data': instance.testData,
    };

ModelTestResponse _$ModelTestResponseFromJson(Map<String, dynamic> json) =>
    ModelTestResponse(
      success: json['success'] as bool,
      responseTimeMs: (json['response_time_ms'] as num).toDouble(),
      result: json['result'] as String?,
      errorMessage: json['error_message'] as String?,
    );

Map<String, dynamic> _$ModelTestResponseToJson(ModelTestResponse instance) =>
    <String, dynamic>{
      'success': instance.success,
      'response_time_ms': instance.responseTimeMs,
      'result': instance.result,
      'error_message': instance.errorMessage,
    };

APIKeyValidationRequest _$APIKeyValidationRequestFromJson(
  Map<String, dynamic> json,
) => APIKeyValidationRequest(
  apiUrl: json['api_url'] as String,
  apiKey: json['api_key'] as String,
  modelId: json['model_id'] as String?,
  modelType: $enumDecode(_$AIModelTypeEnumMap, json['model_type']),
);

Map<String, dynamic> _$APIKeyValidationRequestToJson(
  APIKeyValidationRequest instance,
) => <String, dynamic>{
  'api_url': instance.apiUrl,
  'api_key': instance.apiKey,
  'model_id': instance.modelId,
  'model_type': _$AIModelTypeEnumMap[instance.modelType]!,
};

APIKeyValidationResponse _$APIKeyValidationResponseFromJson(
  Map<String, dynamic> json,
) => APIKeyValidationResponse(
  valid: json['valid'] as bool,
  errorMessage: json['error_message'] as String?,
  testResult: json['test_result'] as String?,
  responseTimeMs: (json['response_time_ms'] as num).toDouble(),
);

Map<String, dynamic> _$APIKeyValidationResponseToJson(
  APIKeyValidationResponse instance,
) => <String, dynamic>{
  'valid': instance.valid,
  'error_message': instance.errorMessage,
  'test_result': instance.testResult,
  'response_time_ms': instance.responseTimeMs,
};
