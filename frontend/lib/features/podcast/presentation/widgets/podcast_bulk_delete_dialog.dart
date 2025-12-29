import 'package:flutter/material.dart';

import '../../../../core/localization/app_localizations.dart';

/// Material 3 AlertDialog for bulk delete confirmation
class PodcastBulkDeleteDialog extends StatelessWidget {
  final List<int> subscriptionIds;
  final int count;
  final VoidCallback onDelete;

  const PodcastBulkDeleteDialog({
    super.key,
    required this.subscriptionIds,
    required this.count,
    required this.onDelete,
  });

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);

    return AlertDialog(
      icon: Icon(
        Icons.warning_amber_rounded,
        color: theme.colorScheme.error,
        size: 48,
      ),
      title: Text(l10n.podcast_bulk_delete_title),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            l10n.podcast_bulk_delete_message(count),
            style: theme.textTheme.bodyMedium,
          ),
          const SizedBox(height: 12),
          Text(
            l10n.podcast_bulk_delete_warning,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.error,
            ),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(l10n.cancel),
        ),
        FilledButton(
          onPressed: () {
            Navigator.of(context).pop();
            onDelete();
          },
          style: FilledButton.styleFrom(
            backgroundColor: theme.colorScheme.error,
            foregroundColor: theme.colorScheme.onError,
          ),
          child: Text(l10n.podcast_bulk_delete_confirm),
        ),
      ],
    );
  }
}
