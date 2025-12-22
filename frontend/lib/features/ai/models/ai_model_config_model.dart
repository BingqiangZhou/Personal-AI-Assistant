import 'package:json_annotation/json_annotation.dart';

part 'ai_model_config_model.g.dart';

/// AI模型类型
enum AIModelType {
  @JsonValue('transcription')
  transcription,
  @JsonValue('text_generation')
  textGeneration,
}

/// AI模型配置
@JsonSerializable(fieldRename: FieldRename.snake)
class AIModelConfigModel {
  final int id;
  final String name;
  final String displayName;
  final String? description;
  final AIModelType modelType;
  final String apiUrl;
  final String? apiKey;  // 返回的会是掩码后的key
  final bool apiKeyEncrypted;
  final String modelId;
  final String provider;
  final int? maxTokens;
  final String? temperature;
  final int timeoutSeconds;
  final int maxRetries;
  final int maxConcurrentRequests;
  final int rateLimitPerMinute;
  final String? costPerInputToken;
  final String? costPerOutputToken;
  final Map<String, dynamic>? extraConfig;
  final bool isActive;
  final bool isDefault;
  final bool isSystem;
  final int usageCount;
  final int successCount;
  final int errorCount;
  final int totalTokensUsed;
  final double successRate;
  final DateTime createdAt;
  final DateTime updatedAt;
  final DateTime? lastUsedAt;

  const AIModelConfigModel({
    required this.id,
    required this.name,
    required this.displayName,
    this.description,
    required this.modelType,
    required this.apiUrl,
    this.apiKey,
    required this.apiKeyEncrypted,
    required this.modelId,
    required this.provider,
    this.maxTokens,
    this.temperature,
    this.timeoutSeconds = 300,
    this.maxRetries = 3,
    this.maxConcurrentRequests = 1,
    this.rateLimitPerMinute = 60,
    this.costPerInputToken,
    this.costPerOutputToken,
    this.extraConfig,
    this.isActive = true,
    this.isDefault = false,
    this.isSystem = false,
    this.usageCount = 0,
    this.successCount = 0,
    this.errorCount = 0,
    this.totalTokensUsed = 0,
    this.successRate = 0.0,
    required this.createdAt,
    required this.updatedAt,
    this.lastUsedAt,
  });

  factory AIModelConfigModel.fromJson(Map<String, dynamic> json) =>
      _$AIModelConfigModelFromJson(json);

  Map<String, dynamic> toJson() => _$AIModelConfigModelToJson(this);

  /// 创建模型配置请求（不包含id等只读字段）
  factory AIModelConfigModel.create({
    required String name,
    required String displayName,
    String? description,
    required AIModelType modelType,
    required String apiUrl,
    String? apiKey,
    required String modelId,
    required String provider,
    int? maxTokens,
    String? temperature,
    int timeoutSeconds = 300,
    int maxRetries = 3,
    int maxConcurrentRequests = 1,
    int rateLimitPerMinute = 60,
    String? costPerInputToken,
    String? costPerOutputToken,
    Map<String, dynamic>? extraConfig,
    bool isActive = true,
    bool isDefault = false,
  }) {
    return AIModelConfigModel(
      id: 0, // 创建时不需要id
      name: name,
      displayName: displayName,
      description: description,
      modelType: modelType,
      apiUrl: apiUrl,
      apiKey: apiKey,
      apiKeyEncrypted: apiKey != null,
      modelId: modelId,
      provider: provider,
      maxTokens: maxTokens,
      temperature: temperature,
      timeoutSeconds: timeoutSeconds,
      maxRetries: maxRetries,
      maxConcurrentRequests: maxConcurrentRequests,
      rateLimitPerMinute: rateLimitPerMinute,
      costPerInputToken: costPerInputToken,
      costPerOutputToken: costPerOutputToken,
      extraConfig: extraConfig,
      isActive: isActive,
      isDefault: isDefault,
      isSystem: false,
      createdAt: DateTime.now(),
      updatedAt: DateTime.now(),
    );
  }

  /// 复制并修改部分字段
  AIModelConfigModel copyWith({
    int? id,
    String? name,
    String? displayName,
    String? description,
    AIModelType? modelType,
    String? apiUrl,
    String? apiKey,
    bool? apiKeyEncrypted,
    String? modelId,
    String? provider,
    int? maxTokens,
    String? temperature,
    int? timeoutSeconds,
    int? maxRetries,
    int? maxConcurrentRequests,
    int? rateLimitPerMinute,
    String? costPerInputToken,
    String? costPerOutputToken,
    Map<String, dynamic>? extraConfig,
    bool? isActive,
    bool? isDefault,
    bool? isSystem,
    int? usageCount,
    int? successCount,
    int? errorCount,
    int? totalTokensUsed,
    double? successRate,
    DateTime? createdAt,
    DateTime? updatedAt,
    DateTime? lastUsedAt,
  }) {
    return AIModelConfigModel(
      id: id ?? this.id,
      name: name ?? this.name,
      displayName: displayName ?? this.displayName,
      description: description ?? this.description,
      modelType: modelType ?? this.modelType,
      apiUrl: apiUrl ?? this.apiUrl,
      apiKey: apiKey ?? this.apiKey,
      apiKeyEncrypted: apiKeyEncrypted ?? this.apiKeyEncrypted,
      modelId: modelId ?? this.modelId,
      provider: provider ?? this.provider,
      maxTokens: maxTokens ?? this.maxTokens,
      temperature: temperature ?? this.temperature,
      timeoutSeconds: timeoutSeconds ?? this.timeoutSeconds,
      maxRetries: maxRetries ?? this.maxRetries,
      maxConcurrentRequests: maxConcurrentRequests ?? this.maxConcurrentRequests,
      rateLimitPerMinute: rateLimitPerMinute ?? this.rateLimitPerMinute,
      costPerInputToken: costPerInputToken ?? this.costPerInputToken,
      costPerOutputToken: costPerOutputToken ?? this.costPerOutputToken,
      extraConfig: extraConfig ?? this.extraConfig,
      isActive: isActive ?? this.isActive,
      isDefault: isDefault ?? this.isDefault,
      isSystem: isSystem ?? this.isSystem,
      usageCount: usageCount ?? this.usageCount,
      successCount: successCount ?? this.successCount,
      errorCount: errorCount ?? this.errorCount,
      totalTokensUsed: totalTokensUsed ?? this.totalTokensUsed,
      successRate: successRate ?? this.successRate,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      lastUsedAt: lastUsedAt ?? this.lastUsedAt,
    );
  }

  /// 获取模型类型的显示名称
  String get modelTypeDisplayName {
    switch (modelType) {
      case AIModelType.transcription:
        return '转录模型';
      case AIModelType.textGeneration:
        return '文本生成模型';
    }
  }

  /// 获取提供商的显示名称
  String get providerDisplayName {
    switch (provider) {
      case 'openai':
        return 'OpenAI';
      case 'siliconflow':
        return '硅基流动';
      case 'anthropic':
        return 'Anthropic';
      case 'azure':
        return 'Azure OpenAI';
      default:
        return provider.toUpperCase();
    }
  }

  /// 是否正在使用中
  bool get isInUse => usageCount > 0;

  /// 获取成功率百分比字符串
  String get successRatePercentage => '${successRate.toStringAsFixed(1)}%';

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is AIModelConfigModel &&
          runtimeType == other.runtimeType &&
          id == other.id;

  @override
  int get hashCode => id.hashCode;

  @override
  String toString() {
    return 'AIModelConfigModel{id: $id, name: $name, displayName: $displayName, modelType: $modelType}';
  }
}

/// AI模型配置列表响应
@JsonSerializable(fieldRename: FieldRename.snake)
class AIModelConfigListResponse {
  final List<AIModelConfigModel> models;
  final int total;
  final int page;
  final int size;
  final int pages;

  const AIModelConfigListResponse({
    required this.models,
    required this.total,
    required this.page,
    required this.size,
    required this.pages,
  });

  factory AIModelConfigListResponse.fromJson(Map<String, dynamic> json) =>
      _$AIModelConfigListResponseFromJson(json);

  Map<String, dynamic> toJson() => _$AIModelConfigListResponseToJson(this);
}

/// 模型使用统计
@JsonSerializable(fieldRename: FieldRename.snake)
class ModelUsageStats {
  final int modelId;
  final String modelName;
  final String modelType;
  final int usageCount;
  final int successCount;
  final int errorCount;
  final double successRate;
  final int totalTokensUsed;
  final DateTime? lastUsedAt;
  final double? totalCost;

  const ModelUsageStats({
    required this.modelId,
    required this.modelName,
    required this.modelType,
    required this.usageCount,
    required this.successCount,
    required this.errorCount,
    required this.successRate,
    required this.totalTokensUsed,
    this.lastUsedAt,
    this.totalCost,
  });

  factory ModelUsageStats.fromJson(Map<String, dynamic> json) =>
      _$ModelUsageStatsFromJson(json);

  Map<String, dynamic> toJson() => _$ModelUsageStatsToJson(this);
}

/// 模型测试请求
@JsonSerializable(fieldRename: FieldRename.snake)
class ModelTestRequest {
  final int modelId;
  final Map<String, dynamic> testData;

  const ModelTestRequest({
    required this.modelId,
    this.testData = const {},
  });

  factory ModelTestRequest.fromJson(Map<String, dynamic> json) =>
      _$ModelTestRequestFromJson(json);

  Map<String, dynamic> toJson() => _$ModelTestRequestToJson(this);
}

/// 模型测试响应
@JsonSerializable(fieldRename: FieldRename.snake)
class ModelTestResponse {
  final bool success;
  final double responseTimeMs;
  final String? result;
  final String? errorMessage;

  const ModelTestResponse({
    required this.success,
    required this.responseTimeMs,
    this.result,
    this.errorMessage,
  });

  factory ModelTestResponse.fromJson(Map<String, dynamic> json) =>
      _$ModelTestResponseFromJson(json);

  Map<String, dynamic> toJson() => _$ModelTestResponseToJson(this);
}

/// API密钥验证请求
@JsonSerializable(fieldRename: FieldRename.snake)
class APIKeyValidationRequest {
  final String apiUrl;
  final String apiKey;
  final String? modelId;
  final AIModelType modelType;

  const APIKeyValidationRequest({
    required this.apiUrl,
    required this.apiKey,
    this.modelId,
    required this.modelType,
  });

  factory APIKeyValidationRequest.fromJson(Map<String, dynamic> json) =>
      _$APIKeyValidationRequestFromJson(json);

  Map<String, dynamic> toJson() => _$APIKeyValidationRequestToJson(this);
}

/// API密钥验证响应
@JsonSerializable(fieldRename: FieldRename.snake)
class APIKeyValidationResponse {
  final bool valid;
  final String? errorMessage;
  final String? testResult;
  final double responseTimeMs;

  const APIKeyValidationResponse({
    required this.valid,
    this.errorMessage,
    this.testResult,
    required this.responseTimeMs,
  });

  factory APIKeyValidationResponse.fromJson(Map<String, dynamic> json) =>
      _$APIKeyValidationResponseFromJson(json);

  Map<String, dynamic> toJson() => _$APIKeyValidationResponseToJson(this);
}