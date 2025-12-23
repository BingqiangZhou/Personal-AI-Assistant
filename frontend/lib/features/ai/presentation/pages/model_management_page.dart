import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

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
    showDialog(
      context: context,
      builder: (context) => ModelCreateDialog(
        initialType: _selectedType,
        onModelCreated: (model) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text('模型 "${model.displayName}" 创建成功'),
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
    showDialog(
      context: context,
      builder: (context) => ModelEditDialog(
        model: model,
        onModelUpdated: (updatedModel) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text('模型 "${updatedModel.displayName}" 更新成功'),
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
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('确认删除'),
        content: Text('确定要删除模型 "${model.displayName}" 吗？'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('取消'),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('删除', style: TextStyle(color: Colors.red)),
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
              content: Text('模型 "${model.displayName}" 已删除'),
              backgroundColor: Colors.green,
            ),
          );
          _refreshModels();
        } else {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('删除失败'),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    }
  }

  void _setAsDefault(AIModelConfigModel model) async {
    final success = await ref
        .read(modelNotifierProvider(model.id).notifier)
        .setAsDefault(_selectedType.toString().split('.').last);

    if (mounted) {
      if (success) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('已将 "${model.displayName}" 设为默认模型'),
            backgroundColor: Colors.green,
          ),
        );
        _refreshModels();
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('设置默认模型失败'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  void _toggleModelActive(AIModelConfigModel model) async {
    final notifier = ref.read(modelNotifierProvider(model.id).notifier);
    final success = await notifier.updateModel({
      'is_active': !model.isActive,
    });

    if (mounted) {
      if (success) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('模型已${model.isActive ? "禁用" : "启用"}'),
            backgroundColor: Colors.green,
          ),
        );
        _refreshModels();
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('操作失败'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final modelListState = ref.watch(modelListProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('AI模型管理'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _refreshModels,
            tooltip: '刷新',
          ),
          IconButton(
            icon: const Icon(Icons.add),
            onPressed: _showCreateModelDialog,
            tooltip: '添加模型',
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
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Row(
        children: [
          // 模型类型选择
          DropdownButton<AIModelType>(
            value: _selectedType,
            items: const [
              DropdownMenuItem(
                value: AIModelType.transcription,
                child: Text('转录模型'),
              ),
              DropdownMenuItem(
                value: AIModelType.textGeneration,
                child: Text('文本生成模型'),
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
              decoration: const InputDecoration(
                hintText: '搜索模型名称、描述...',
                prefixIcon: Icon(Icons.search),
                border: OutlineInputBorder(),
                contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 8),
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
              const Text('仅显示活跃'),
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
              '加载失败: ${state.error}',
              style: const TextStyle(color: Colors.red),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: _refreshModels,
              child: const Text('重试'),
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
            const Text(
              '暂无模型配置',
              style: TextStyle(fontSize: 18, color: Colors.grey),
            ),
            const SizedBox(height: 16),
            ElevatedButton.icon(
              onPressed: _showCreateModelDialog,
              icon: const Icon(Icons.add),
              label: const Text('添加第一个模型'),
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
