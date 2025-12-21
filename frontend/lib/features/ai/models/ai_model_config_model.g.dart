// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'ai_model_config_model.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

AIModelConfigModel _$AIModelConfigModelFromJson(Map<String, dynamic> json) =>
    AIModelConfigModel(
      id: (json['id'] as num).toInt(),
      name: json['name'] as String,
      displayName: json['displayName'] as String,
      description: json['description'] as String?,
      modelType: $enumDecode(_$AIModelTypeEnumMap, json['modelType']),
      apiUrl: json['apiUrl'] as String,
      apiKey: json['apiKey'] as String?,
      apiKeyEncrypted: json['apiKeyEncrypted'] as bool,
      modelId: json['modelId'] as String,
      provider: json['provider'] as String,
      maxTokens: (json['maxTokens'] as num?)?.toInt(),
      temperature: json['temperature'] as String?,
      timeoutSeconds: (json['timeoutSeconds'] as num?)?.toInt() ?? 300,
      maxRetries: (json['maxRetries'] as num?)?.toInt() ?? 3,
      maxConcurrentRequests:
          (json['maxConcurrentRequests'] as num?)?.toInt() ?? 1,
      rateLimitPerMinute: (json['rateLimitPerMinute'] as num?)?.toInt() ?? 60,
      costPerInputToken: json['costPerInputToken'] as String?,
      costPerOutputToken: json['costPerOutputToken'] as String?,
      extraConfig: json['extraConfig'] as Map<String, dynamic>?,
      isActive: json['isActive'] as bool? ?? true,
      isDefault: json['isDefault'] as bool? ?? false,
      isSystem: json['isSystem'] as bool? ?? false,
      usageCount: (json['usageCount'] as num?)?.toInt() ?? 0,
      successCount: (json['successCount'] as num?)?.toInt() ?? 0,
      errorCount: (json['errorCount'] as num?)?.toInt() ?? 0,
      totalTokensUsed: (json['totalTokensUsed'] as num?)?.toInt() ?? 0,
      successRate: (json['successRate'] as num?)?.toDouble() ?? 0.0,
      createdAt: DateTime.parse(json['createdAt'] as String),
      updatedAt: DateTime.parse(json['updatedAt'] as String),
      lastUsedAt: json['lastUsedAt'] == null
          ? null
          : DateTime.parse(json['lastUsedAt'] as String),
    );

Map<String, dynamic> _$AIModelConfigModelToJson(AIModelConfigModel instance) =>
    <String, dynamic>{
      'id': instance.id,
      'name': instance.name,
      'displayName': instance.displayName,
      'description': instance.description,
      'modelType': _$AIModelTypeEnumMap[instance.modelType]!,
      'apiUrl': instance.apiUrl,
      'apiKey': instance.apiKey,
      'apiKeyEncrypted': instance.apiKeyEncrypted,
      'modelId': instance.modelId,
      'provider': instance.provider,
      'maxTokens': instance.maxTokens,
      'temperature': instance.temperature,
      'timeoutSeconds': instance.timeoutSeconds,
      'maxRetries': instance.maxRetries,
      'maxConcurrentRequests': instance.maxConcurrentRequests,
      'rateLimitPerMinute': instance.rateLimitPerMinute,
      'costPerInputToken': instance.costPerInputToken,
      'costPerOutputToken': instance.costPerOutputToken,
      'extraConfig': instance.extraConfig,
      'isActive': instance.isActive,
      'isDefault': instance.isDefault,
      'isSystem': instance.isSystem,
      'usageCount': instance.usageCount,
      'successCount': instance.successCount,
      'errorCount': instance.errorCount,
      'totalTokensUsed': instance.totalTokensUsed,
      'successRate': instance.successRate,
      'createdAt': instance.createdAt.toIso8601String(),
      'updatedAt': instance.updatedAt.toIso8601String(),
      'lastUsedAt': instance.lastUsedAt?.toIso8601String(),
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
      modelId: (json['modelId'] as num).toInt(),
      modelName: json['modelName'] as String,
      modelType: json['modelType'] as String,
      usageCount: (json['usageCount'] as num).toInt(),
      successCount: (json['successCount'] as num).toInt(),
      errorCount: (json['errorCount'] as num).toInt(),
      successRate: (json['successRate'] as num).toDouble(),
      totalTokensUsed: (json['totalTokensUsed'] as num).toInt(),
      lastUsedAt: json['lastUsedAt'] == null
          ? null
          : DateTime.parse(json['lastUsedAt'] as String),
      totalCost: (json['totalCost'] as num?)?.toDouble(),
    );

Map<String, dynamic> _$ModelUsageStatsToJson(ModelUsageStats instance) =>
    <String, dynamic>{
      'modelId': instance.modelId,
      'modelName': instance.modelName,
      'modelType': instance.modelType,
      'usageCount': instance.usageCount,
      'successCount': instance.successCount,
      'errorCount': instance.errorCount,
      'successRate': instance.successRate,
      'totalTokensUsed': instance.totalTokensUsed,
      'lastUsedAt': instance.lastUsedAt?.toIso8601String(),
      'totalCost': instance.totalCost,
    };

ModelTestRequest _$ModelTestRequestFromJson(Map<String, dynamic> json) =>
    ModelTestRequest(
      modelId: (json['modelId'] as num).toInt(),
      testData: json['testData'] as Map<String, dynamic>? ?? const {},
    );

Map<String, dynamic> _$ModelTestRequestToJson(ModelTestRequest instance) =>
    <String, dynamic>{
      'modelId': instance.modelId,
      'testData': instance.testData,
    };

ModelTestResponse _$ModelTestResponseFromJson(Map<String, dynamic> json) =>
    ModelTestResponse(
      success: json['success'] as bool,
      responseTimeMs: (json['responseTimeMs'] as num).toDouble(),
      result: json['result'] as String?,
      errorMessage: json['errorMessage'] as String?,
    );

Map<String, dynamic> _$ModelTestResponseToJson(ModelTestResponse instance) =>
    <String, dynamic>{
      'success': instance.success,
      'responseTimeMs': instance.responseTimeMs,
      'result': instance.result,
      'errorMessage': instance.errorMessage,
    };

APIKeyValidationRequest _$APIKeyValidationRequestFromJson(
  Map<String, dynamic> json,
) => APIKeyValidationRequest(
  apiUrl: json['apiUrl'] as String,
  apiKey: json['apiKey'] as String,
  modelId: json['modelId'] as String?,
  modelType: $enumDecode(_$AIModelTypeEnumMap, json['modelType']),
);

Map<String, dynamic> _$APIKeyValidationRequestToJson(
  APIKeyValidationRequest instance,
) => <String, dynamic>{
  'apiUrl': instance.apiUrl,
  'apiKey': instance.apiKey,
  'modelId': instance.modelId,
  'modelType': _$AIModelTypeEnumMap[instance.modelType]!,
};

APIKeyValidationResponse _$APIKeyValidationResponseFromJson(
  Map<String, dynamic> json,
) => APIKeyValidationResponse(
  valid: json['valid'] as bool,
  errorMessage: json['errorMessage'] as String?,
  testResult: json['testResult'] as String?,
  responseTimeMs: (json['responseTimeMs'] as num).toDouble(),
);

Map<String, dynamic> _$APIKeyValidationResponseToJson(
  APIKeyValidationResponse instance,
) => <String, dynamic>{
  'valid': instance.valid,
  'errorMessage': instance.errorMessage,
  'testResult': instance.testResult,
  'responseTimeMs': instance.responseTimeMs,
};
