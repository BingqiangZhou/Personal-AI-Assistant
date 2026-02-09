import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/services/app_update_service.dart';
import 'package:personal_ai_assistant/shared/models/github_release.dart';
import 'package:personal_ai_assistant/features/settings/presentation/providers/app_update_provider.dart';

/// App Update Dialog / 应用更新对话框
///
/// Material 3 styled dialog for displaying available app updates.
/// Shows release information, download options, and user actions.
class AppUpdateDialog extends ConsumerStatefulWidget {
  final GitHubRelease release;
  final String currentVersion;

  const AppUpdateDialog({
    super.key,
    required this.release,
    required this.currentVersion,
  });

  /// Show the dialog
  static Future<void> show({
    required BuildContext context,
    required GitHubRelease release,
    required String currentVersion,
  }) {
    return showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => AppUpdateDialog(
        release: release,
        currentVersion: currentVersion,
      ),
    );
  }

  @override
  ConsumerState<AppUpdateDialog> createState() => _AppUpdateDialogState();
}

class _AppUpdateDialogState extends ConsumerState<AppUpdateDialog> {
  bool _isDownloading = false;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final isMobile = MediaQuery.of(context).size.width < 600;
    final screenWidth = MediaQuery.of(context).size.width;
    final dialogWidth = screenWidth < 600 ? screenWidth - 8 : 500.0;

    return AlertDialog(
      insetPadding: isMobile ? const EdgeInsets.symmetric(horizontal: 4, vertical: 16) : null,
      title: Row(
        children: [
          Icon(
            Icons.system_update_alt,
            color: theme.colorScheme.primary,
            size: 28,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(l10n.update_new_version_available),
                Text(
                  '${widget.currentVersion} → ${widget.release.version}',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.primary,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
      content: SizedBox(
        width: dialogWidth,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Release info
              _buildReleaseInfo(context),
              const SizedBox(height: 16),

              // Release notes
              _buildReleaseNotes(context),
            ],
          ),
        ),
      ),
      actions: isMobile ? _buildMobileActions(context, theme) : _buildDesktopActions(context, theme),
    );
  }

  /// Desktop actions layout
  List<Widget> _buildDesktopActions(BuildContext context, ThemeData theme) {
    final l10n = AppLocalizations.of(context)!;
    return [
      // Use Row to control alignment
      Row(
        children: [
          // Skip this version (left)
          TextButton.icon(
            onPressed: () => _handleSkip(context),
            icon: const Icon(Icons.skip_next, size: 18),
            label: Text(l10n.update_skip_this_version),
            style: TextButton.styleFrom(
              foregroundColor: theme.colorScheme.onSurfaceVariant,
            ),
          ),

          const Spacer(),

          // Later + Download (right)
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text(l10n.update_later),
          ),

          const SizedBox(width: 8),

          // Download button (primary action)
          FilledButton.icon(
            onPressed: _isDownloading ? null : () => _handleDownload(context),
            icon: _isDownloading
                ? const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.download, size: 18),
            label: Text(l10n.update_download),
            style: FilledButton.styleFrom(
              backgroundColor: theme.colorScheme.primary,
              foregroundColor: theme.colorScheme.onPrimary,
            ),
          ),
        ],
      ),
    ];
  }

  /// Mobile actions layout
  List<Widget> _buildMobileActions(BuildContext context, ThemeData theme) {
    final l10n = AppLocalizations.of(context)!;
    return [
      // Skip this version (top row, right aligned)
      Align(
        alignment: Alignment.centerRight,
        child: TextButton.icon(
          onPressed: () => _handleSkip(context),
          icon: const Icon(Icons.skip_next, size: 18),
          label: Text(l10n.update_skip_this_version),
          style: TextButton.styleFrom(
            foregroundColor: theme.colorScheme.onSurfaceVariant,
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
          ),
        ),
      ),

      // Bottom row: Later (left) + Download (right)
      Row(
        children: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text(l10n.update_later),
          ),
          const Spacer(),
          // Download button (primary action)
          FilledButton.icon(
            onPressed: _isDownloading ? null : () => _handleDownload(context),
            icon: _isDownloading
                ? const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.download, size: 18),
            label: Text(l10n.update_download),
            style: FilledButton.styleFrom(
              backgroundColor: theme.colorScheme.primary,
              foregroundColor: theme.colorScheme.onPrimary,
            ),
          ),
        ],
      ),
    ];
  }

  Widget _buildReleaseInfo(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final isMobile = MediaQuery.of(context).size.width < 600;

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Version row
          Row(
            children: [
              Icon(
                Icons.info_outline,
                size: 18,
                color: theme.colorScheme.primary,
              ),
              const SizedBox(width: 8),
              Text(
                l10n.update_latest_version,
                style: theme.textTheme.labelMedium,
              ),
              const Spacer(),
              Text(
                'v${widget.release.version}',
                style: theme.textTheme.titleMedium?.copyWith(
                  color: theme.colorScheme.primary,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          // Release date and file size - aligned with icon
          if (isMobile) ...[
            // Mobile: vertical layout
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(
                      Icons.calendar_today,
                      size: 14,
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        '${l10n.update_published_at}: ${widget.release.formattedPublishedDate}',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ),
                  ],
                ),
                if (widget.release.assets.isNotEmpty) ...[
                  const SizedBox(height: 4),
                  Row(
                    children: [
                      Icon(
                        Icons.file_download,
                        size: 14,
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          '${l10n.update_file_size}: ${widget.release.assets.first.formattedSize}',
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ),
                    ],
                  ),
                ],
              ],
            ),
          ] else ...[
            // Desktop: horizontal layout
            Row(
              children: [
                Icon(
                  Icons.calendar_today,
                  size: 14,
                  color: theme.colorScheme.onSurfaceVariant,
                ),
                const SizedBox(width: 8),
                Text(
                  '${l10n.update_published_at}: ${widget.release.formattedPublishedDate}',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
                if (widget.release.assets.isNotEmpty) ...[
                  const SizedBox(width: 16),
                  Icon(
                    Icons.file_download,
                    size: 14,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    '${l10n.update_file_size}: ${widget.release.assets.first.formattedSize}',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
              ],
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildReleaseNotes(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final notes = AppUpdateService.parseReleaseNotes(widget.release.body);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(
              Icons.description,
              size: 18,
              color: theme.colorScheme.primary,
            ),
            const SizedBox(width: 8),
            Text(
              l10n.update_release_notes,
              style: theme.textTheme.labelMedium,
            ),
          ],
        ),
        const SizedBox(height: 8),
        Container(
          constraints: const BoxConstraints(maxHeight: 200),
          child: ListView.builder(
            shrinkWrap: true,
            itemCount: notes.length,
            itemBuilder: (context, index) {
              return Padding(
                padding: const EdgeInsets.only(bottom: 4),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '• ',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                    Expanded(
                      child: Text(
                        notes[index],
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
        ),
      ],
    );
  }

  void _handleDownload(BuildContext context) async {
    setState(() {
      _isDownloading = true;
    });

    try {
      final downloadUrl = widget.release.primaryDownloadUrl;

      if (downloadUrl == null) {
        // No download URL available, open in browser
        final uri = Uri.parse(widget.release.htmlUrl);
        if (await canLaunchUrl(uri)) {
          await launchUrl(uri, mode: LaunchMode.externalApplication);
        }
      } else if (AppUpdateService.supportsBackgroundDownload) {
        // Use native background download on Android
        final service = ref.read(appUpdateServiceProvider);
        final success = await service.startBackgroundDownload(
          downloadUrl: downloadUrl,
          fileName: _extractFileName(downloadUrl),
        );

        if (!success && context.mounted) {
          final l10n = AppLocalizations.of(context)!;
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(l10n.update_download_failed),
              backgroundColor: Theme.of(context).colorScheme.error,
            ),
          );
        } else if (success && context.mounted) {
          // Download started, close dialog and show message
          Navigator.of(context).pop();
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: const Text('Downloading in background...'),
              duration: const Duration(seconds: 5),
            ),
          );
        }
      } else {
        // Fallback to browser for other platforms
        final uri = Uri.parse(downloadUrl);
        if (await canLaunchUrl(uri)) {
          await launchUrl(uri, mode: LaunchMode.externalApplication);
        } else {
          // Fallback to release page
          final releaseUri = Uri.parse(widget.release.htmlUrl);
          if (await canLaunchUrl(releaseUri)) {
            await launchUrl(releaseUri, mode: LaunchMode.externalApplication);
          }
        }
      }
    } catch (e) {
      if (context.mounted) {
        final l10n = AppLocalizations.of(context)!;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('${l10n.update_download_failed}: $e'),
            backgroundColor: Theme.of(context).colorScheme.error,
          ),
        );
      }
    } finally {
      if (context.mounted) {
        setState(() {
          _isDownloading = false;
        });
      }
    }
  }

  /// Extract filename from download URL
  String _extractFileName(String url) {
    final uri = Uri.parse(url);
    final pathSegments = uri.pathSegments;
    if (pathSegments.isNotEmpty) {
      final filename = pathSegments.last;
      if (filename.endsWith('.apk')) {
        return filename;
      }
    }
    return 'app_update.apk';
  }

  void _handleSkip(BuildContext context) {
    ref.read(appUpdateProvider.notifier).skipVersion();
    Navigator.of(context).pop();
  }
}

/// Manual Update Check Dialog / 手动检查更新对话框
///
/// Shows a loading state while checking for updates,
/// then displays the result (update available or up to date).
class ManualUpdateCheckDialog extends ConsumerStatefulWidget {
  const ManualUpdateCheckDialog({super.key});

  static Future<void> show(BuildContext context) {
    return showDialog(
      context: context,
      barrierDismissible: true,
      builder: (context) => const ManualUpdateCheckDialog(),
    );
  }

  @override
  ConsumerState<ManualUpdateCheckDialog> createState() =>
      _ManualUpdateCheckDialogState();
}

class _ManualUpdateCheckDialogState
    extends ConsumerState<ManualUpdateCheckDialog> {
  @override
  void initState() {
    super.initState();
    // Trigger check on dialog open
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(manualUpdateCheckProvider.notifier).check();
    });
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final state = ref.watch(manualUpdateCheckProvider);
    final screenWidth = MediaQuery.of(context).size.width;
    final dialogWidth = screenWidth < 600 ? screenWidth - 8 : 400.0;
    final isMobile = screenWidth < 600;

    return AlertDialog(
      insetPadding: isMobile ? const EdgeInsets.symmetric(horizontal: 4, vertical: 16) : null,
      title: Text(l10n.update_check_updates),
      content: SizedBox(
        width: dialogWidth,
        child: _buildContent(context, state),
      ),
      actions: _buildActions(context, state),
    );
  }

  Widget _buildContent(BuildContext context, AppUpdateState state) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);

    if (state.isLoading) {
      return Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const CircularProgressIndicator(),
          const SizedBox(height: 16),
          Text(l10n.update_checking),
        ],
      );
    }

    if (state.error != null) {
      return Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.error_outline,
            size: 48,
            color: theme.colorScheme.error,
          ),
          const SizedBox(height: 16),
          Text(
            l10n.update_check_failed,
            style: theme.textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          Text(
            state.error!,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      );
    }

    if (state.hasUpdate && state.latestRelease != null) {
      final release = state.latestRelease!;
      return Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                Icons.new_releases,
                color: theme.colorScheme.primary,
                size: 32,
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '${l10n.update_new_version_available}: v${release.version}',
                      style: theme.textTheme.titleMedium?.copyWith(
                        color: theme.colorScheme.primary,
                      ),
                    ),
                    Text(
                      '${l10n.update_current_version}: v${state.currentVersion}',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Text(l10n.update_available_description),
        ],
      );
    }

    // Up to date
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(
          Icons.check_circle_outline,
          size: 48,
          color: theme.colorScheme.primary,
        ),
        const SizedBox(height: 16),
        Text(
          l10n.update_up_to_date,
          style: theme.textTheme.titleMedium?.copyWith(
            color: theme.colorScheme.primary,
          ),
        ),
        const SizedBox(height: 8),
        Text(
          'v${state.currentVersion}',
          style: theme.textTheme.bodyMedium?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
      ],
    );
  }

  List<Widget> _buildActions(BuildContext context, AppUpdateState state) {
    final l10n = AppLocalizations.of(context)!;

    if (state.isLoading) {
      return [];
    }

    if (state.error != null) {
      return [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(l10n.close),
        ),
        TextButton(
          onPressed: () {
            ref.read(manualUpdateCheckProvider.notifier).check();
          },
          child: Text(l10n.update_try_again),
        ),
      ];
    }

    if (state.hasUpdate && state.latestRelease != null) {
      return [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(l10n.cancel),
        ),
        FilledButton(
          onPressed: () {
            Navigator.of(context).pop();
            AppUpdateDialog.show(
              context: context,
              release: state.latestRelease!,
              currentVersion: state.currentVersion,
            );
          },
          child: Text(l10n.update_download),
        ),
      ];
    }

    return [
      TextButton(
        onPressed: () => Navigator.of(context).pop(),
        child: Text(l10n.ok),
      ),
    ];
  }
}

/// Simple "No Update" SnackBar for quick feedback
void showUpdateAvailableSnackBar({
  required BuildContext context,
  required GitHubRelease release,
  VoidCallback? onUpdate,
}) {
  final l10n = AppLocalizations.of(context)!;

  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Row(
        children: [
          const Icon(Icons.system_update_alt, size: 20),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              '${l10n.update_new_version_available}: v${release.version}',
            ),
          ),
        ],
      ),
      action: SnackBarAction(
        label: l10n.update_download,
        onPressed: () {
          ScaffoldMessenger.of(context).hideCurrentSnackBar();
          AppUpdateDialog.show(
            context: context,
            release: release,
            currentVersion: AppUpdateService.getCurrentVersionSync(),
          );
        },
      ),
      duration: const Duration(seconds: 10),
      behavior: SnackBarBehavior.floating,
    ),
  );
}
