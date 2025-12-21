import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../data/services/ai_model_api_service.dart';
import '../../data/repositories/ai_model_repository.dart';
import '../../models/ai_model_config_model.dart';
import '../../../../core/providers/core_providers.dart';

// API服务Provider
final aiModelApiServiceProvider = Provider<AIModelApiService>((ref) {
  final dioClient = ref.watch(dioClientProvider);
  return AIModelApiService(dioClient.dio);
});

// Repository Provider
final aiModelRepositoryProvider = Provider<AIModelRepository>((ref) {
  final apiService = ref.watch(aiModelApiServiceProvider);
  return AIModelRepository(apiService);
});

// 模型列表状态
class ModelListState {
  final List<AIModelConfigModel> models;
  final bool isLoading;
  final String? error;
  final int currentPage;
  final int totalPages;
  final int total;

  const ModelListState({
    this.models = const [],
    this.isLoading = false,
    this.error,
    this.currentPage = 1,
    this.totalPages = 1,
    this.total = 0,
  });

  ModelListState copyWith({
    List<AIModelConfigModel>? models,
    bool? isLoading,
    String? error,
    int? currentPage,
    int? totalPages,
    int? total,
  }) {
    return ModelListState(
      models: models ?? this.models,
      isLoading: isLoading ?? this.isLoading,
      error: error ?? this.error,
      currentPage: currentPage ?? this.currentPage,
      totalPages: totalPages ?? this.totalPages,
      total: total ?? this.total,
    );
  }
}

// 模型列表Notifier - 使用Notifier（Riverpod 3.x推荐）
class ModelListNotifier extends Notifier<ModelListState> {
  @override
  ModelListState build() {
    return const ModelListState();
  }

  late AIModelRepository _repository;

  void _initRepository() {
    _repository = ref.read(aiModelRepositoryProvider);
  }

  /// 加载模型列表
  Future<void> loadModels({
    String? modelType,
    bool? isActive,
    String? provider,
    int page = 1,
    int size = 20,
    String? search,
  }) async {
    _initRepository();
    state = state.copyWith(isLoading: true, error: null);

    try {
      final response = await _repository.getModels(
        modelType: modelType,
        isActive: isActive,
        provider: provider,
        page: page,
        size: size,
        search: search,
      );

      state = state.copyWith(
        models: response.models,
        isLoading: false,
        currentPage: page,
        totalPages: response.pages,
        total: response.total,
      );
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
    }
  }

  /// 刷新列表
  Future<void> refresh({
    String? modelType,
    bool? isActive,
    String? provider,
    String? search,
  }) async {
    await loadModels(
      modelType: modelType,
      isActive: isActive,
      provider: provider,
      page: 1,
      search: search,
    );
  }

  /// 加载更多
  Future<void> loadMore({
    String? modelType,
    bool? isActive,
    String? provider,
    String? search,
  }) async {
    if (state.isLoading || state.currentPage >= state.totalPages) return;

    await loadModels(
      modelType: modelType,
      isActive: isActive,
      provider: provider,
      page: state.currentPage + 1,
      search: search,
    );
  }

  /// 添加模型到列表
  void addModel(AIModelConfigModel model) {
    state = state.copyWith(
      models: [model, ...state.models],
      total: state.total + 1,
    );
  }

  /// 更新列表中的模型
  void updateModel(AIModelConfigModel updatedModel) {
    final models = state.models.map((model) {
      return model.id == updatedModel.id ? updatedModel : model;
    }).toList();

    state = state.copyWith(models: models);
  }

  /// 从列表中移除模型
  void removeModel(int modelId) {
    final models = state.models.where((model) => model.id != modelId).toList();
    state = state.copyWith(
      models: models,
      total: state.total - 1,
    );
  }

  /// 清除错误
  void clearError() {
    state = state.copyWith(error: null);
  }
}

// 模型列表Provider
final modelListProvider = NotifierProvider<ModelListNotifier, ModelListState>(ModelListNotifier.new);

// 单个模型状态
class ModelState {
  final AIModelConfigModel? model;
  final bool isLoading;
  final String? error;
  final bool isSaving;
  final bool isDeleting;
  final bool isTesting;

  const ModelState({
    this.model,
    this.isLoading = false,
    this.error,
    this.isSaving = false,
    this.isDeleting = false,
    this.isTesting = false,
  });

  ModelState copyWith({
    AIModelConfigModel? model,
    bool? isLoading,
    String? error,
    bool? isSaving,
    bool? isDeleting,
    bool? isTesting,
  }) {
    return ModelState(
      model: model ?? this.model,
      isLoading: isLoading ?? this.isLoading,
      error: error ?? this.error,
      isSaving: isSaving ?? this.isSaving,
      isDeleting: isDeleting ?? this.isDeleting,
      isTesting: isTesting ?? this.isTesting,
    );
  }
}

// 单个模型Notifier - 使用Notifier.family
class ModelNotifier extends Notifier<ModelState> {
  late final int modelId;
  late final AIModelRepository _repository;

  @override
  ModelState build() {
    // In Riverpod 3.x, family parameters are passed via ref.watch
    // We need to get them from the provider's context
    return const ModelState();
  }

  // Called by the provider factory to set up the notifier
  void setup(int id, AIModelRepository repo) {
    modelId = id;
    _repository = repo;
  }

  // Getter to expose current model
  AIModelConfigModel? get currentModel => state.model;

  /// 加载模型详情
  Future<void> loadModel() async {
    state = state.copyWith(isLoading: true, error: null);

    try {
      final model = await _repository.getModel(modelId);
      state = state.copyWith(
        model: model,
        isLoading: false,
      );
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
    }
  }

  /// 更新模型
  Future<bool> updateModel(Map<String, dynamic> updateData) async {
    state = state.copyWith(isSaving: true, error: null);

    try {
      final updatedModel = await _repository.updateModel(modelId, updateData);
      state = state.copyWith(
        model: updatedModel,
        isSaving: false,
      );

      // 同时更新列表中的模型
      ref.read(modelListProvider.notifier).updateModel(updatedModel);

      return true;
    } catch (e) {
      state = state.copyWith(
        isSaving: false,
        error: e.toString(),
      );
      return false;
    }
  }

  /// 删除模型
  Future<bool> deleteModel() async {
    state = state.copyWith(isDeleting: true, error: null);

    try {
      await _repository.deleteModel(modelId);

      // 从列表中移除
      ref.read(modelListProvider.notifier).removeModel(modelId);

      state = state.copyWith(isDeleting: false);
      return true;
    } catch (e) {
      state = state.copyWith(
        isDeleting: false,
        error: e.toString(),
      );
      return false;
    }
  }

  /// 测试模型
  Future<ModelTestResponse?> testModel({
    Map<String, dynamic>? testData,
  }) async {
    state = state.copyWith(isTesting: true, error: null);

    try {
      final response = await _repository.testModel(
        modelId,
        testData: testData ?? {},
      );

      state = state.copyWith(isTesting: false);
      return response;
    } catch (e) {
      state = state.copyWith(
        isTesting: false,
        error: e.toString(),
      );
      return null;
    }
  }

  /// 设置为默认模型
  Future<bool> setAsDefault(String modelType) async {
    state = state.copyWith(isSaving: true, error: null);

    try {
      final updatedModel = await _repository.setDefaultModel(modelId, modelType);
      state = state.copyWith(
        model: updatedModel,
        isSaving: false,
      );

      // 同时更新列表中的模型
      ref.read(modelListProvider.notifier).updateModel(updatedModel);

      return true;
    } catch (e) {
      state = state.copyWith(
        isSaving: false,
        error: e.toString(),
      );
      return false;
    }
  }

  /// 清除错误
  void clearError() {
    state = state.copyWith(error: null);
  }
}

// 单个模型Provider - 使用自定义family工厂
// Riverpod 3.x的NotifierProvider.family在某些情况下可能有兼容性问题
// 这里使用Provider.family返回Notifier，然后通过额外的Provider暴露状态
final modelProvider = Provider.family<ModelNotifier, int>((ref, modelId) {
  final repository = ref.read(aiModelRepositoryProvider);
  final notifier = ModelNotifier();
  notifier.setup(modelId, repository);
  return notifier;
});

// 状态访问Provider - 包装modelProvider以暴露状态
final modelStateProvider = Provider.family<ModelState, int>((ref, modelId) {
  // 这里我们无法直接watch到ModelNotifier的state变化
  // 所以需要使用StateNotifierProvider或者改变设计
  // 为简化，我们将使用FutureProvider来加载单个模型
  return const ModelState();
});

// 单个模型详情Future Provider（替代方案，更简单可靠）
final modelDetailProvider = FutureProvider.family<AIModelConfigModel?, int>((ref, modelId) async {
  final repository = ref.watch(aiModelRepositoryProvider);
  try {
    return await repository.getModel(modelId);
  } catch (e) {
    return null;
  }
});

// 创建模型状态
class CreateModelState {
  final bool isCreating;
  final String? error;
  final AIModelConfigModel? createdModel;

  const CreateModelState({
    this.isCreating = false,
    this.error,
    this.createdModel,
  });

  CreateModelState copyWith({
    bool? isCreating,
    String? error,
    AIModelConfigModel? createdModel,
  }) {
    return CreateModelState(
      isCreating: isCreating ?? this.isCreating,
      error: error ?? this.error,
      createdModel: createdModel ?? this.createdModel,
    );
  }
}

// 创建模型Notifier
class CreateModelNotifier extends Notifier<CreateModelState> {
  late AIModelRepository _repository;

  @override
  CreateModelState build() {
    _repository = ref.read(aiModelRepositoryProvider);
    return const CreateModelState();
  }

  /// 创建新模型
  Future<AIModelConfigModel?> createModel(Map<String, dynamic> modelData) async {
    state = state.copyWith(isCreating: true, error: null);

    try {
      final createdModel = await _repository.createModel(modelData);

      state = state.copyWith(
        isCreating: false,
        createdModel: createdModel,
      );

      // 添加到列表
      ref.read(modelListProvider.notifier).addModel(createdModel);

      return createdModel;
    } catch (e) {
      state = state.copyWith(
        isCreating: false,
        error: e.toString(),
      );
      return null;
    }
  }

  /// 重置状态
  void reset() {
    state = const CreateModelState();
  }

  /// 清除错误
  void clearError() {
    state = state.copyWith(error: null);
  }
}

// 创建模型Provider
final createModelProvider = NotifierProvider<CreateModelNotifier, CreateModelState>(CreateModelNotifier.new);

// 默认模型Provider
final defaultModelsProvider = FutureProvider.family<Map<String, AIModelConfigModel?>, String>((ref, modelType) async {
  final repository = ref.watch(aiModelRepositoryProvider);
  try {
    final model = await repository.getDefaultModel(modelType);
    return {modelType: model};
  } catch (e) {
    return {modelType: null};
  }
});

// 活跃模型Provider
final activeModelsProvider = FutureProvider.family<List<AIModelConfigModel>, String>((ref, modelType) async {
  final repository = ref.watch(aiModelRepositoryProvider);
  return repository.getActiveModels(modelType);
});

// 模型统计Provider
final modelStatsProvider = FutureProvider.family<ModelUsageStats, int>((ref, modelId) async {
  final repository = ref.watch(aiModelRepositoryProvider);
  return repository.getModelStats(modelId);
});

// 类型统计Provider
final typeStatsProvider = FutureProvider.family<List<ModelUsageStats>, String>((ref, modelType) async {
  final repository = ref.watch(aiModelRepositoryProvider);
  return repository.getTypeStats(modelType);
});
