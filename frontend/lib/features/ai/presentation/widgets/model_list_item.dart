import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../../core/localization/app_localizations.dart';

import '../../models/ai_model_config_model.dart';

class ModelListItem extends ConsumerWidget {
  final AIModelConfigModel model;
  final VoidCallback onEdit;
  final VoidCallback onTest;
  final VoidCallback onDelete;
  final VoidCallback onSetDefault;
  final VoidCallback onToggleActive;

  const ModelListItem({
    super.key,
    required this.model,
    required this.onEdit,
    required this.onTest,
    required this.onDelete,
    required this.onSetDefault,
    required this.onToggleActive,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context)!;
    // Note: We're not watching individual model state here since the callbacks handle updates
    // The list state is managed by modelListProvider which is updated by the callbacks

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: ListTile(
        leading: _buildLeading(l10n),
        title: _buildTitle(l10n),
        subtitle: _buildSubtitle(),
        trailing: _buildTrailing(context, l10n, false), // No loading state shown in list item
        onTap: onEdit,
        enabled: true,
      ),
    );
  }

  Widget _buildLeading(AppLocalizations l10n) {
    return Container(
      width: 48,
      height: 48,
      decoration: BoxDecoration(
        color: model.isActive ? Colors.green.withValues(alpha: 0.1) : Colors.grey.withValues(alpha: 0.1),
        shape: BoxShape.circle,
        border: Border.all(
          color: model.isDefault ? Colors.blue : Colors.transparent,
          width: 2,
        ),
      ),
      child: Icon(
        model.modelType == AIModelType.transcription ? Icons.record_voice_over : Icons.auto_awesome,
        color: model.isActive
            ? (model.isDefault ? Colors.blue : Colors.green)
            : Colors.grey,
        size: 24,
      ),
    );
  }

  Widget _buildTitle(AppLocalizations l10n) {
    return Row(
      children: [
        Text(
          model.displayName,
          style: TextStyle(
            fontWeight: FontWeight.bold,
            fontSize: 16,
            color: model.isActive ? Colors.black87 : Colors.grey,
          ),
        ),
        if (model.isDefault) ...[
          const SizedBox(width: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
            decoration: BoxDecoration(
              color: Colors.blue.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(4),
              border: Border.all(color: Colors.blue),
            ),
            child: Text(
              l10n.ai_model_default,
              style: TextStyle(
                color: Colors.blue,
                fontSize: 10,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ],
        if (model.isSystem) ...[
          const SizedBox(width: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
            decoration: BoxDecoration(
              color: Colors.purple.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(4),
              border: Border.all(color: Colors.purple),
            ),
            child: Text(
              l10n.ai_model_system,
              style: TextStyle(
                color: Colors.purple,
                fontSize: 10,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildSubtitle() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SizedBox(height: 4),
        Text(
          model.name,
          style: TextStyle(
            fontSize: 12,
            color: Colors.grey[600],
          ),
        ),
        const SizedBox(height: 2),
        Row(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: Colors.grey.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(
                model.providerDisplayName,
                style: TextStyle(
                  fontSize: 11,
                  color: Colors.grey[700],
                ),
              ),
            ),
            const SizedBox(width: 6),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: Colors.grey.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(
                model.modelId,
                style: TextStyle(
                  fontSize: 11,
                  color: Colors.grey[700],
                ),
              ),
            ),
          ],
        ),
        if (model.description != null && model.description!.isNotEmpty) ...[
          const SizedBox(height: 4),
          Text(
            model.description!,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: 12,
              color: Colors.grey[600],
            ),
          ),
        ],
        const SizedBox(height: 4),
        // 使用统计
        if (model.isInUse)
          Row(
            children: [
              Icon(Icons.analytics, size: 12, color: Colors.green[700]),
              const SizedBox(width: 4),
              Text(
                '使用: ${model.usageCount} | 成功率: ${model.successRatePercentage}',
                style: TextStyle(
                  fontSize: 11,
                  color: Colors.green[700],
                ),
              ),
            ],
          ),
      ],
    );
  }

  Widget _buildTrailing(BuildContext context, AppLocalizations l10n, bool isSaving) {
    if (isSaving) {
      return const SizedBox(
        width: 24,
        height: 24,
        child: Center(child: CircularProgressIndicator(strokeWidth: 2)),
      );
    }

    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        // 激活/禁用切换
        IconButton(
          icon: Icon(
            model.isActive ? Icons.toggle_on : Icons.toggle_off,
            color: model.isActive ? Colors.green : Colors.grey,
            size: 28,
          ),
          onPressed: onToggleActive,
          tooltip: model.isActive ? l10n.ai_model_disable : l10n.ai_model_enable,
        ),
        // 更多菜单
        PopupMenuButton<String>(
          icon: const Icon(Icons.more_vert),
          onSelected: (value) {
            switch (value) {
              case 'edit':
                onEdit();
                break;
              case 'test':
                onTest();
                break;
              case 'set_default':
                onSetDefault();
                break;
              case 'delete':
                onDelete();
                break;
            }
          },
          itemBuilder: (context) => [
            PopupMenuItem(value: 'edit', child: Text(l10n.ai_edit_config)),
            PopupMenuItem(value: 'test', child: Text(l10n.ai_test_connection)),
            PopupMenuItem(
              enabled: !model.isDefault,
              value: 'set_default',
              child: Text(l10n.ai_set_as_default)
            ),
            PopupMenuItem(
              value: 'delete',
              child: Text(l10n.delete, style: TextStyle(color: Colors.red)),
            ),
          ],
        ),
      ],
    );
  }
}