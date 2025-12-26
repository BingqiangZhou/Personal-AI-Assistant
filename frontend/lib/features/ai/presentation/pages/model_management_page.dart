import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../providers/ai_model_provider.dart';
import '../widgets/model_list_item.dart';
import '../widgets/model_create_dialog.dart';
import '../widgets/model_edit_dialog.dart';
import '../widgets/model_test_dialog.dart';
import '../../models/ai_model_config_model.dart';

class ModelManagementPage extends ConsumerStatefulWidget {
  const ModelManagementPage({super.key});

  @override
  ConsumerState<ModelManagementPage> createState() => _ModelManagementPageState();
}

class _ModelManagementPageState extends ConsumerState<ModelManagementPage> {
  AIModelType _selectedType = AIModelType.transcription;
  String _searchQuery = '';
  bool _showOnlyActive = true;

  @override
  void initState() {
    super.initState();
    _loadModels();
  }

  void _loadModels() {
    ref.read(modelListProvider.notifier).loadModels(
          modelType: _selectedType.toString().split('.').last,
          isActive: _showOnlyActive,
          search: _searchQuery.isEmpty ? null : _searchQuery,
        );
  }

  void _refreshModels() {
    ref.read(modelListProvider.notifier).refresh(
          modelType: _selectedType.toString().split('.').last,
          isActive: _showOnlyActive,
          search: _searchQuery.isEmpty ? null : _searchQuery,
        );
  }

  void _showCreateModelDialog() {
    final l10n = AppLocalizations.of(context)!;
    showDialog(
      context: context,
      builder: (context) => ModelCreateDialog(
        initialType: _selectedType,
        onModelCreated: (model) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text(l10n.ai_model_created(model.displayName)),
                backgroundColor: Colors.green,
              ),
            );
            _refreshModels();
          }
        },
      ),
    );
  }

  void _showEditModelDialog(AIModelConfigModel model) {
    final l10n = AppLocalizations.of(context)!;
    showDialog(
      context: context,
      builder: (context) => ModelEditDialog(
        model: model,
        onModelUpdated: (updatedModel) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text(l10n.ai_model_updated_msg(updatedModel.displayName)),
                backgroundColor: Colors.green,
              ),
            );
            _refreshModels();
          }
        },
      ),
    );
  }

  void _showTestModelDialog(AIModelConfigModel model) {
    showDialog(
      context: context,
      builder: (context) => ModelTestDialog(model: model),
    );
  }

  void _deleteModel(AIModelConfigModel model) async {
    final l10n = AppLocalizations.of(context)!;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.delete_confirm_title),
        content: Text(l10n.ai_confirm_delete_model),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: Text(l10n.cancel),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: Text(l10n.delete, style: const TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      final notifier = ref.read(modelNotifierProvider(model.id).notifier);
      final success = await notifier.deleteModel();
      if (mounted) {
        if (success) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(l10n.ai_model_deleted_msg(model.displayName)),
              backgroundColor: Colors.green,
            ),
          );
          _refreshModels();
        } else {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(l10n.ai_delete_failed),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    }
  }

  void _setAsDefault(AIModelConfigModel model) async {
    final l10n = AppLocalizations.of(context)!;
    final success = await ref
        .read(modelNotifierProvider(model.id).notifier)
        .setAsDefault(_selectedType.toString().split('.').last);

    if (mounted) {
      if (success) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(l10n.ai_set_as_default(model.displayName)),
            backgroundColor: Colors.green,
          ),
        );
        _refreshModels();
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(l10n.ai_set_default_failed),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  void _toggleModelActive(AIModelConfigModel model) async {
    final l10n = AppLocalizations.of(context)!;
    final notifier = ref.read(modelNotifierProvider(model.id).notifier);
    final success = await notifier.updateModel({
      'is_active': !model.isActive,
    });

    if (mounted) {
      if (success) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(model.isActive ? l10n.ai_model_disabled : l10n.ai_model_enabled),
            backgroundColor: Colors.green,
          ),
        );
        _refreshModels();
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(l10n.ai_operation_failed),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final modelListState = ref.watch(modelListProvider);

    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.ai_model_management),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _refreshModels,
            tooltip: l10n.refresh,
          ),
          IconButton(
            icon: const Icon(Icons.add),
            onPressed: _showCreateModelDialog,
            tooltip: l10n.ai_add_model,
          ),
        ],
      ),
      body: Column(
        children: [
          // 过滤器和搜索栏
          _buildFilterBar(),
          const Divider(),
          // 内容区域
          Expanded(
            child: _buildContent(modelListState),
          ),
        ],
      ),
    );
  }

  Widget _buildFilterBar() {
    final l10n = AppLocalizations.of(context)!;
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Row(
        children: [
          // 模型类型选择
          DropdownButton<AIModelType>(
            value: _selectedType,
            items: [
              DropdownMenuItem(
                value: AIModelType.transcription,
                child: Text(l10n.ai_transcription_model),
              ),
              DropdownMenuItem(
                value: AIModelType.textGeneration,
                child: Text(l10n.ai_text_generation_model),
              ),
            ],
            onChanged: (value) {
              if (value != null) {
                setState(() {
                  _selectedType = value;
                  _loadModels();
                });
              }
            },
          ),
          const SizedBox(width: 16),
          // 搜索框
          Expanded(
            child: TextField(
              decoration: InputDecoration(
                hintText: l10n.ai_search_models,
                prefixIcon: const Icon(Icons.search),
                border: const OutlineInputBorder(),
                contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              ),
              onChanged: (value) {
                setState(() {
                  _searchQuery = value;
                });
                // 延迟搜索，避免频繁请求
                Future.delayed(const Duration(milliseconds: 500), () {
                  _loadModels();
                });
              },
            ),
          ),
          const SizedBox(width: 16),
          // 活跃状态切换
          Row(
            children: [
              Text(l10n.ai_only_show_active),
              Switch(
                value: _showOnlyActive,
                onChanged: (value) {
                  setState(() {
                    _showOnlyActive = value;
                    _loadModels();
                  });
                },
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildContent(ModelListState state) {
    final l10n = AppLocalizations.of(context)!;
    if (state.isLoading && state.models.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }

    if (state.error != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 64, color: Colors.red),
            const SizedBox(height: 16),
            Text(
              l10n.ai_load_failed(state.error.toString()),
              style: const TextStyle(color: Colors.red),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: _refreshModels,
              child: Text(l10n.retry),
            ),
          ],
        ),
      );
    }

    if (state.models.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.model_training, size: 64, color: Colors.grey),
            const SizedBox(height: 16),
            Text(
              l10n.ai_no_models_configured_yet,
              style: const TextStyle(fontSize: 18, color: Colors.grey),
            ),
            const SizedBox(height: 16),
            ElevatedButton.icon(
              onPressed: _showCreateModelDialog,
              icon: const Icon(Icons.add),
              label: Text(l10n.ai_add_first_model_btn),
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: () async {
        _refreshModels();
      },
      child: Column(
        children: [
          Expanded(
            child: ListView.builder(
              itemCount: state.models.length,
              itemBuilder: (context, index) {
                final model = state.models[index];
                return ModelListItem(
                  model: model,
                  onEdit: () => _showEditModelDialog(model),
                  onTest: () => _showTestModelDialog(model),
                  onDelete: () => _deleteModel(model),
                  onSetDefault: () => _setAsDefault(model),
                  onToggleActive: () => _toggleModelActive(model),
                );
              },
            ),
          ),
          // 加载更多
          if (state.isLoading && state.models.isNotEmpty)
            const Padding(
              padding: EdgeInsets.all(16.0),
              child: Center(child: CircularProgressIndicator()),
            ),
        ],
      ),
    );
  }
}
