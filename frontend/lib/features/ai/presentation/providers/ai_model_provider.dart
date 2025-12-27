import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:riverpod/riverpod.dart';

import '../../data/services/ai_model_api_service.dart';
import '../../data/repositories/ai_model_repository.dart';
import '../../models/ai_model_config_model.dart';
import '../../../../core/providers/core_providers.dart';
import '../../../../core/network/exceptions/network_exceptions.dart';
import '../../../auth/presentation/providers/auth_provider.dart';

// API Service Provider
final aiModelApiServiceProvider = Provider<AIModelApiService>((ref) {
  final dioClient = ref.watch(dioClientProvider);
  return AIModelApiService(dioClient.dio);
});

// Repository Provider
final aiModelRepositoryProvider = Provider<AIModelRepository>((ref) {
  final apiService = ref.watch(aiModelApiServiceProvider);
  return AIModelRepository(apiService);
});

// Model List State
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

// Model List Notifier - Uses Notifier (Recommended for Riverpod 3.x)
class ModelListNotifier extends Notifier<ModelListState> {
  @override
  ModelListState build() {
    return const ModelListState();
  }

  late AIModelRepository _repository;

  void _initRepository() {
    _repository = ref.read(aiModelRepositoryProvider);
  }

  /// Load model list
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
      if (e is AuthenticationException) {
        ref.read(authProvider.notifier).logout();
      }
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
    }
  }

  /// Refresh list
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

  /// Load more
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

  /// Add model to list
  void addModel(AIModelConfigModel model) {
    state = state.copyWith(
      models: [model, ...state.models],
      total: state.total + 1,
    );
  }

  /// Update model in list
  void updateModel(AIModelConfigModel updatedModel) {
    final models = state.models.map((model) {
      return model.id == updatedModel.id ? updatedModel : model;
    }).toList();

    state = state.copyWith(models: models);
  }

  /// Remove model from list
  void removeModel(int modelId) {
    final models = state.models.where((model) => model.id != modelId).toList();
    state = state.copyWith(
      models: models,
      total: state.total - 1,
    );
  }

  /// Clear error
  void clearError() {
    state = state.copyWith(error: null);
  }
}

// Model List Provider
final modelListProvider = NotifierProvider<ModelListNotifier, ModelListState>(ModelListNotifier.new);

// Single Model State
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

// Single Model Notifier - Uses Notifier pattern for Riverpod 3.0
class ModelNotifier extends Notifier<ModelState> {
  late AIModelRepository _repository;
  final int modelId;

  ModelNotifier(this.modelId);

  @override
  ModelState build() {
    _repository = ref.read(aiModelRepositoryProvider);
    return const ModelState();
  }

  // Getter to expose current model
  AIModelConfigModel? get currentModel => state.model;

  /// Load model details
  Future<void> loadModel() async {
    state = state.copyWith(isLoading: true, error: null);

    try {
      final model = await _repository.getModel(modelId);
      state = state.copyWith(
        model: model,
        isLoading: false,
      );

    } catch (e) {
      if (e is AuthenticationException) {
        ref.read(authProvider.notifier).logout();
      }
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
    }
  }

  /// Update model
  Future<bool> updateModel(Map<String, dynamic> updateData) async {
    state = state.copyWith(isSaving: true, error: null);

    try {
      final updatedModel = await _repository.updateModel(modelId, updateData);
      state = state.copyWith(
        model: updatedModel,
        isSaving: false,
      );

      // Also update model in list
      ref.read(modelListProvider.notifier).updateModel(updatedModel);

      return true;
    } catch (e) {
      if (e is AuthenticationException) {
        ref.read(authProvider.notifier).logout();
      }
      state = state.copyWith(
        isSaving: false,
        error: e.toString(),
      );
      return false;
    }
  }

  /// Delete model
  Future<bool> deleteModel() async {
    state = state.copyWith(isDeleting: true, error: null);

    try {
      await _repository.deleteModel(modelId);

      // Remove from list
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

  /// Test model
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

  /// Set as default model
  Future<bool> setAsDefault(String modelType) async {
    state = state.copyWith(isSaving: true, error: null);

    try {
      final updatedModel = await _repository.setDefaultModel(modelId, modelType);
      state = state.copyWith(
        model: updatedModel,
        isSaving: false,
      );

      // Also update model in list
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

  /// Clear error
  void clearError() {
    state = state.copyWith(error: null);
  }
}

// Single Model Notifier Provider
final modelNotifierProvider = NotifierProvider.family<ModelNotifier, ModelState, int>(ModelNotifier.new);

// Single Model Details Future Provider (Alternative, simpler and more reliable)
final modelDetailProvider = FutureProvider.family<AIModelConfigModel?, int>((ref, modelId) async {
  final repository = ref.watch(aiModelRepositoryProvider);
  try {
    return await repository.getModel(modelId);
  } catch (e) {
    return null;
  }
});

// Create Model State
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

// Create Model Notifier
class CreateModelNotifier extends Notifier<CreateModelState> {
  late AIModelRepository _repository;

  @override
  CreateModelState build() {
    _repository = ref.read(aiModelRepositoryProvider);
    return const CreateModelState();
  }

  /// Create new model
  Future<AIModelConfigModel?> createModel(Map<String, dynamic> modelData) async {
    state = state.copyWith(isCreating: true, error: null);

    try {
      final createdModel = await _repository.createModel(modelData);

      state = state.copyWith(
        isCreating: false,
        createdModel: createdModel,
      );

      // Add to list
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

  /// Reset state
  void reset() {
    state = const CreateModelState();
  }

  /// Clear error
  void clearError() {
    state = state.copyWith(error: null);
  }
}

// Create Model Provider
final createModelProvider = NotifierProvider<CreateModelNotifier, CreateModelState>(CreateModelNotifier.new);

// Default Model Provider
final defaultModelsProvider = FutureProvider.family<Map<String, AIModelConfigModel?>, String>((ref, modelType) async {
  final repository = ref.watch(aiModelRepositoryProvider);
  try {
    final model = await repository.getDefaultModel(modelType);
    return {modelType: model};
  } catch (e) {
    return {modelType: null};
  }
});

// Active Models Provider
final activeModelsProvider = FutureProvider.family<List<AIModelConfigModel>, String>((ref, modelType) async {
  final repository = ref.watch(aiModelRepositoryProvider);
  return repository.getActiveModels(modelType);
});

// Model Stats Provider
final modelStatsProvider = FutureProvider.family<ModelUsageStats, int>((ref, modelId) async {
  final repository = ref.watch(aiModelRepositoryProvider);
  return repository.getModelStats(modelId);
});

// Type Stats Provider
final typeStatsProvider = FutureProvider.family<List<ModelUsageStats>, String>((ref, modelType) async {
  final repository = ref.watch(aiModelRepositoryProvider);
  return repository.getTypeStats(modelType);
});
