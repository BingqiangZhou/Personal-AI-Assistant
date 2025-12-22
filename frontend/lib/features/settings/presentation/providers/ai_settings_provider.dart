import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../../core/providers/core_providers.dart';
import '../../../ai/data/services/ai_model_api_service.dart';
import '../../../ai/models/ai_model_config_model.dart';

// API Service Provider
final aiModelApiServiceProvider = Provider<AIModelApiService>((ref) {
  final dioClient = ref.watch(dioClientProvider);
  return AIModelApiService(dioClient.dio);
});

// Active Models Providers
final activeTranscriptionModelsProvider = FutureProvider<List<AIModelConfigModel>>((ref) async {
  final apiService = ref.watch(aiModelApiServiceProvider);
  return apiService.getActiveModels('transcription');
});

final activeTextModelsProvider = FutureProvider<List<AIModelConfigModel>>((ref) async {
  final apiService = ref.watch(aiModelApiServiceProvider);
  return apiService.getActiveModels('text_generation');
});

// Supported Models Lists (Hardcoded for now as per config, but ideally fetched or just used for dropdown)
// Fetching all models to populate dropdowns
final transcriptionModelsListProvider = FutureProvider<List<AIModelConfigModel>>((ref) async {
  final apiService = ref.watch(aiModelApiServiceProvider);
  final response = await apiService.getModels(modelType: 'transcription', size: 100);
  return response.models;
});

final textModelsListProvider = FutureProvider<List<AIModelConfigModel>>((ref) async {
  final apiService = ref.watch(aiModelApiServiceProvider);
  final response = await apiService.getModels(modelType: 'text_generation', size: 100);
  return response.models;
});

// Settings Save State
class AISettingsState {
  final bool isLoading;
  final String? error;
  final bool success;

  AISettingsState({this.isLoading = false, this.error, this.success = false});

  AISettingsState copyWith({bool? isLoading, String? error, bool? success}) {
    return AISettingsState(
      isLoading: isLoading ?? this.isLoading,
      error: error,
      success: success ?? this.success,
    );
  }
}

class AISettingsController extends Notifier<AISettingsState> {
  @override
  AISettingsState build() {
    return AISettingsState();
  }

  Future<void> saveSettings({
    required String type,
    required String apiUrl,
    required String? apiKey,
    required String modelId, // The specific model ID (e.g. gpt-4o)
    required String name, // Config name (e.g. gpt-4o)
    required String provider,
  }) async {
    state = state.copyWith(isLoading: true, error: null, success: false);
    final apiService = ref.read(aiModelApiServiceProvider);

    try {
      // 1. Check if model config exists by name
      final allModels = await apiService.getModels(search: name, modelType: type);
      AIModelConfigModel? existingModel;
      
      if (allModels.models.isNotEmpty) {
        existingModel = allModels.models.firstWhere((m) => m.name == name, orElse: () => allModels.models.first);
      }

      final modelData = {
        'name': name,
        'model_type': type,
        'api_url': apiUrl,
        'model_id': modelId,
        'provider': provider,
        'is_active': true,
        // Only send API key if provided (not empty)
        if (apiKey != null && apiKey.isNotEmpty) 'api_key': apiKey,
      };

      if (existingModel != null) {
        // Update
        await apiService.updateModel(existingModel.id, modelData);
        // Ensure it is default
        await apiService.setDefaultModel(existingModel.id, type);
      } else {
        // Create
        final newModel = await apiService.createModel({
            ...modelData,
            'display_name': name,
            'is_default': true,
        });
      }

      // Refresh providers
      if (type == 'transcription') {
        ref.refresh(activeTranscriptionModelsProvider);
        ref.refresh(transcriptionModelsListProvider);
      } else {
        ref.refresh(activeTextModelsProvider);
        ref.refresh(textModelsListProvider);
      }

      state = state.copyWith(isLoading: false, success: true);
    } catch (e) {
      state = state.copyWith(isLoading: false, error: e.toString());
    }
  }
}

final aiSettingsControllerProvider = NotifierProvider<AISettingsController, AISettingsState>(AISettingsController.new);
