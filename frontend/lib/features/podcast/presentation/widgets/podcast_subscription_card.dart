import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../data/models/podcast_subscription_model.dart';
import 'platform_badge.dart';

class PodcastSubscriptionCard extends ConsumerWidget {
  final PodcastSubscriptionModel subscription;
  final VoidCallback? onTap;
  final VoidCallback? onDelete;
  final VoidCallback? onRefresh;
  final VoidCallback? onReparse;

  const PodcastSubscriptionCard({
    super.key,
    required this.subscription,
    this.onTap,
    this.onDelete,
    this.onRefresh,
    this.onReparse,
  });

  /// Helper method to safely get shade colors from MaterialColor or regular Color
  Color? _getShadeColor(Color color, int shade) {
    if (color is MaterialColor) {
      switch (shade) {
        case 600:
          return color.shade600;
        case 700:
          return color.shade700;
        case 800:
          return color.shade800;
        case 50:
          return color.shade50;
        default:
          return null;
      }
    }
    return null;
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final lastFetched = subscription.lastFetchedAt;

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: InkWell(
        onTap: onTap ?? () {
          context.push('/podcast/episodes/${subscription.id}');
        },
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Podcast image
                  Container(
                    width: 80,
                    height: 80,
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(12),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.1),
                          blurRadius: 4,
                          offset: const Offset(0, 2),
                        ),
                      ],
                    ),
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(12),
                      child: subscription.imageUrl != null
                          ? Image.network(
                              subscription.imageUrl!,
                              width: 80,
                              height: 80,
                              fit: BoxFit.cover,
                              errorBuilder: (context, error, stackTrace) {
                                return Container(
                                  color: theme.primaryColor.withValues(alpha: 0.1),
                                  child: Icon(
                                    Icons.podcasts,
                                    size: 40,
                                    color: theme.primaryColor,
                                  ),
                                );
                              },
                            )
                          : Container(
                              color: theme.primaryColor.withValues(alpha: 0.1),
                              child: Icon(
                                Icons.podcasts,
                                size: 40,
                                color: theme.primaryColor,
                              ),
                            ),
                    ),
                  ),
                  const SizedBox(width: 16),
                  // Title and description - expanded to take remaining space
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          subscription.title,
                          style: theme.textTheme.titleMedium?.copyWith(
                            fontWeight: FontWeight.bold,
                          ),
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                        if (subscription.description != null) ...[
                          const SizedBox(height: 4),
                          Text(
                              subscription.description!,
                              style: theme.textTheme.bodySmall?.copyWith(
                                color: theme.textTheme.bodySmall?.color?.withValues(alpha: 0.7),
                              ),
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                            ),
                        ],
                        const SizedBox(height: 8),
                        Row(
                          children: [
                            Flexible(
                              child: Wrap(
                                spacing: 8,
                                runSpacing: 4,
                                children: [
                                  _buildStatusChip(context, subscription.status),
                                  PlatformBadge(platform: subscription.platform),
                                  // Episodes count
                                  _buildInlineStatItem(
                                    context,
                                    Icons.library_music,
                                    '${subscription.episodeCount}',
                                  ),
                                  // Unplayed count
                                  _buildInlineStatItem(
                                    context,
                                    Icons.play_circle_outline,
                                    '${subscription.unplayedCount}',
                                  ),
                                ],
                              ),
                            ),
                            Container(
                              margin: const EdgeInsets.only(left: 8),
                              decoration: BoxDecoration(
                                color: theme.colorScheme.surface.withValues(alpha: 0.6),
                                borderRadius: BorderRadius.circular(8),
                                border: Border.all(
                                  color: theme.dividerColor.withValues(alpha: 0.4),
                                  width: 1,
                                ),
                              ),
                              child: PopupMenuButton<String>(
                                icon: Icon(
                                  Icons.more_vert,
                                  size: 20,
                                  color: theme.colorScheme.onSurface.withValues(alpha: 0.8),
                                ),
                                onSelected: (value) {
                                  switch (value) {
                                    case 'refresh':
                                      onRefresh?.call();
                                      break;
                                    case 'reparse':
                                      onReparse?.call();
                                      break;
                                    case 'delete':
                                      _showDeleteConfirmation(context);
                                      break;
                                  }
                                },
                                itemBuilder: (context) => [
                                  const PopupMenuItem(
                                    value: 'refresh',
                                    child: Row(
                                      children: [
                                        Icon(Icons.refresh),
                                        SizedBox(width: 8),
                                        Text('Refresh'),
                                      ],
                                    ),
                                  ),
                                  const PopupMenuItem(
                                    value: 'reparse',
                                    child: Row(
                                      children: [
                                        Icon(Icons.sync_problem),
                                        SizedBox(width: 8),
                                        Text('Reparse All'),
                                      ],
                                    ),
                                  ),
                                  const PopupMenuItem(
                                    value: 'delete',
                                    child: Row(
                                      children: [
                                        Icon(Icons.delete, color: Colors.red),
                                        SizedBox(width: 8),
                                        Text('Delete', style: TextStyle(color: Colors.red)),
                                      ],
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildStatusChip(BuildContext context, String status) {
    String text;
    IconData icon;
    Color color;

    switch (status) {
      case 'active':
        color = const Color(0xFF4CAF50);
        text = 'Active';
        icon = Icons.check_circle;
        break;
      case 'error':
        color = const Color(0xFFE57373);
        text = 'Error';
        icon = Icons.error;
        break;
      case 'pending':
        color = const Color(0xFFFFB74D);
        text = 'Pending';
        icon = Icons.pending;
        break;
      default:
        color = const Color(0xFF90A4AE);
        text = status;
        icon = Icons.help;
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            icon,
            size: 12,
            color: color,
          ),
          const SizedBox(width: 4),
          Text(
            text,
            style: TextStyle(
              fontSize: 11,
              color: color,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInlineStatItem(BuildContext context, IconData icon, String value) {
    final theme = Theme.of(context);

    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(
          icon,
          size: 14,
          color: const Color(0xFF64B5F6),
        ),
        const SizedBox(width: 4),
        Text(
          value,
          style: theme.textTheme.bodySmall?.copyWith(
            fontWeight: FontWeight.w600,
            color: const Color(0xFF64B5F6),
            fontSize: 12,
          ),
        ),
      ],
    );
  }

  void _showDeleteConfirmation(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.settings_delete_confirm_title),
        content: Text(
          'Are you sure you want to delete "${subscription.title}"? This will also delete all episodes associated with this podcast.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text(l10n.cancel),
          ),
          TextButton(
            onPressed: () {
              Navigator.of(context).pop();
              onDelete?.call();
            },
            style: TextButton.styleFrom(foregroundColor: Colors.red),
            child: Text(l10n.delete),
          ),
        ],
      ),
    );
  }
}