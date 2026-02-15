import 'package:flutter/material.dart';
import 'package:personal_ai_assistant/core/theme/app_colors.dart';
import 'package:flutter_markdown_plus/flutter_markdown_plus.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/services/app_update_service.dart';
import 'package:personal_ai_assistant/core/widgets/top_floating_notice.dart';
import 'package:personal_ai_assistant/shared/models/github_release.dart';
import 'package:personal_ai_assistant/features/settings/presentation/providers/app_update_provider.dart';

Color _updateAccentColor(ThemeData theme) {
  return theme.colorScheme.primary;
}

Color _updateAccentOnColor(ThemeData theme) {
  return theme.brightness == Brightness.dark
      ? Colors.white
      : theme.colorScheme.onPrimary;
}

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
      builder: (context) =>
          AppUpdateDialog(release: release, currentVersion: currentVersion),
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
    final accentColor = _updateAccentColor(theme);
    final isMobile = MediaQuery.of(context).size.width < 600;
    final screenWidth = MediaQuery.of(context).size.width;
    final dialogWidth = screenWidth < 600 ? screenWidth - 32 : 500.0;

    return AlertDialog(
      insetPadding: isMobile ? const EdgeInsets.all(16) : null,
      title: Row(
        children: [
          Icon(
            Icons.system_update_alt,
            color: accentColor,
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
                    color: accentColor,
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
      actions: isMobile
          ? _buildMobileActions(context, theme)
          : _buildDesktopActions(context, theme),
    );
  }

  /// Desktop actions layout
  List<Widget> _buildDesktopActions(BuildContext context, ThemeData theme) {
    final l10n = AppLocalizations.of(context)!;
    final accentColor = _updateAccentColor(theme);
    final accentOnColor = _updateAccentOnColor(theme);
    return [
      // Use Row to control alignment
      Row(
        children: [
          // Skip this version (left)
          TextButton.icon(
            onPressed: () => _handleSkip(context),
            icon: const Icon(Icons.skip_next, size: 18),
            label: Text(l10n.update_skip_this_version),
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
              backgroundColor: accentColor,
              foregroundColor: accentOnColor,
            ),
          ),
        ],
      ),
    ];
  }

  /// Mobile actions layout
  List<Widget> _buildMobileActions(BuildContext context, ThemeData theme) {
    final l10n = AppLocalizations.of(context)!;
    final accentColor = _updateAccentColor(theme);
    final accentOnColor = _updateAccentOnColor(theme);
    return [
      // Skip this version (top row, right aligned)
      Align(
        alignment: Alignment.centerRight,
        child: TextButton.icon(
          onPressed: () => _handleSkip(context),
          icon: const Icon(Icons.skip_next, size: 18),
          label: Text(l10n.update_skip_this_version),
          style: TextButton.styleFrom(
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
              backgroundColor: accentColor,
              foregroundColor: accentOnColor,
            ),
          ),
        ],
      ),
    ];
  }

  Widget _buildReleaseInfo(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final accentColor = _updateAccentColor(theme);
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
                color: accentColor,
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  l10n.update_latest_version,
                  style: theme.textTheme.labelMedium,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              const SizedBox(width: 8),
              Text(
                'v${widget.release.version}',
                style: theme.textTheme.titleMedium?.copyWith(
                  color: accentColor,
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
    final accentColor = _updateAccentColor(theme);
    final releaseNotes = widget.release.body.trim();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(Icons.description, size: 18, color: accentColor),
            const SizedBox(width: 8),
            Text(l10n.update_release_notes, style: theme.textTheme.labelMedium),
          ],
        ),
        const SizedBox(height: 8),
        Container(
          constraints: const BoxConstraints(maxHeight: 200),
          child: releaseNotes.isEmpty
              ? Text(
                  l10n.no_data,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                )
              : SingleChildScrollView(
                  child: MarkdownBody(
                    data: releaseNotes,
                    onTapLink: (text, href, title) {
                      _handleReleaseNotesLinkTap(href);
                    },
                    styleSheet: MarkdownStyleSheet(
                      p: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                      h1: theme.textTheme.titleMedium?.copyWith(
                        color: theme.colorScheme.onSurface,
                        fontWeight: FontWeight.bold,
                      ),
                      h2: theme.textTheme.titleSmall?.copyWith(
                        color: theme.colorScheme.onSurface,
                        fontWeight: FontWeight.bold,
                      ),
                      h3: theme.textTheme.bodyMedium?.copyWith(
                        color: theme.colorScheme.onSurface,
                        fontWeight: FontWeight.bold,
                      ),
                      listBullet: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                      strong: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurface,
                        fontWeight: FontWeight.bold,
                      ),
                      code: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurface,
                        backgroundColor:
                            theme.colorScheme.surfaceContainerHighest,
                      ),
                      codeblockPadding: const EdgeInsets.all(12),
                      codeblockDecoration: BoxDecoration(
                        color: theme.colorScheme.surfaceContainerHighest,
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(
                          color: theme.colorScheme.outlineVariant,
                        ),
                      ),
                      blockquotePadding: const EdgeInsets.all(12),
                      blockquoteDecoration: BoxDecoration(
                        color: theme.colorScheme.surfaceContainerHighest,
                        borderRadius: BorderRadius.circular(12),
                        border: Border(
                          left: BorderSide(color: accentColor, width: 3),
                        ),
                      ),
                      horizontalRuleDecoration: BoxDecoration(
                        border: Border(
                          top: BorderSide(color: theme.colorScheme.outlineVariant),
                        ),
                      ),
                      a: theme.textTheme.bodySmall?.copyWith(
                        color: accentColor,
                        decoration: TextDecoration.underline,
                      ),
                    ),
                  ),
                ),
        ),
      ],
    );
  }

  Future<void> _handleReleaseNotesLinkTap(String? href) async {
    if (href == null || href.isEmpty) {
      return;
    }

    try {
      final uri = Uri.parse(href);
      final canOpen = await canLaunchUrl(uri);
      if (!mounted) return;
      if (!canOpen) {
        _showReleaseNotesLinkError();
        return;
      }

      final opened = await launchUrl(uri, mode: LaunchMode.externalApplication);
      if (!mounted) return;
      if (!opened) {
        _showReleaseNotesLinkError();
      }
    } catch (_) {
      if (!mounted) return;
      _showReleaseNotesLinkError();
    }
  }

  void _showReleaseNotesLinkError() {
    if (!mounted) return;
    final l10n = AppLocalizations.of(context)!;
    showTopFloatingNotice(
      context,
      message: l10n.update_download_failed,
      isError: true,
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
          showTopFloatingNotice(
            context,
            message: l10n.update_download_failed,
            isError: true,
          );
        } else if (success && context.mounted) {
          // Download started, close dialog and show message
          final l10n = AppLocalizations.of(context)!;
          showTopFloatingNotice(
            context,
            message: l10n.downloading_in_background,
            duration: const Duration(seconds: 5),
          );
          Navigator.of(context).pop();
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
        showTopFloatingNotice(
          context,
          message: '${l10n.update_download_failed}: $e',
          isError: true,
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
  static bool _isShowing = false;

  static Future<void> show(BuildContext context) {
    if (_isShowing) return Future.value();
    _isShowing = true;
    return showDialog(
      context: context,
      barrierDismissible: true,
      builder: (context) => const ManualUpdateCheckDialog(),
    ).whenComplete(() {
      _isShowing = false;
    });
  }

  @override
  ConsumerState<ManualUpdateCheckDialog> createState() =>
      _ManualUpdateCheckDialogState();
}

class _ManualUpdateCheckDialogState
    extends ConsumerState<ManualUpdateCheckDialog> {
  bool _redirectingToUpdateDialog = false;

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
    _maybeRedirectToDetailedDialog(context, state);
    final screenWidth = MediaQuery.of(context).size.width;
    final dialogWidth = screenWidth < 600 ? screenWidth - 32 : 400.0;
    final isMobile = screenWidth < 600;

    return AlertDialog(
      insetPadding: isMobile ? const EdgeInsets.all(16) : null,
      title: Text(l10n.update_check_updates),
      content: SizedBox(
        width: dialogWidth,
        child: _buildContent(context, state),
      ),
      actions: _buildActions(context, state),
    );
  }

  void _maybeRedirectToDetailedDialog(
    BuildContext context,
    AppUpdateState state,
  ) {
    final shouldRedirect =
        !state.isLoading &&
        state.error == null &&
        state.hasUpdate &&
        state.latestRelease != null &&
        !_redirectingToUpdateDialog;

    if (!shouldRedirect) {
      return;
    }

    _redirectingToUpdateDialog = true;
    final release = state.latestRelease!;
    final currentVersion = state.currentVersion;

    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      Navigator.of(context).pop();
      AppUpdateDialog.show(
        context: context,
        release: release,
        currentVersion: currentVersion,
      );
    });
  }

  Widget _buildContent(BuildContext context, AppUpdateState state) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final accentColor = _updateAccentColor(theme);

    if (state.isLoading) {
      return Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          CircularProgressIndicator(color: accentColor),
          const SizedBox(height: 16),
          Text(l10n.update_checking),
        ],
      );
    }

    if (state.error != null) {
      return Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.error_outline, size: 48, color: theme.colorScheme.error),
          const SizedBox(height: 16),
          Text(l10n.update_check_failed, style: theme.textTheme.titleMedium),
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
      return const SizedBox.shrink();
    }

    // Up to date
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(
          Icons.check_circle_outline,
          size: 48,
          color: accentColor,
        ),
        const SizedBox(height: 16),
        Text(
          l10n.update_up_to_date,
          style: theme.textTheme.titleMedium?.copyWith(
            color: accentColor,
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
      return [];
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
