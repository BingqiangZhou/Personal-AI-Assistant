import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:flutter_widget_from_html/flutter_widget_from_html.dart';
import '../../../../core/localization/app_localizations.dart';

import '../../data/models/podcast_episode_model.dart';
import '../../core/utils/html_sanitizer.dart';
import '../../../../core/utils/app_logger.dart' as logger;

class ShownotesDisplayWidget extends ConsumerStatefulWidget {
  final PodcastEpisodeDetailResponse episode;

  const ShownotesDisplayWidget({
    super.key,
    required this.episode,
  });

  @override
  ConsumerState<ShownotesDisplayWidget> createState() => ShownotesDisplayWidgetState();
}

class ShownotesDisplayWidgetState extends ConsumerState<ShownotesDisplayWidget> {
  final ScrollController _scrollController = ScrollController();

  /// 滚动到顶部
  void scrollToTop() {
    if (_scrollController.hasClients) {
      _scrollController.animateTo(
        0.0,
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeInOut,
      );
    }
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    // Try to get shownotes from different sources
    final shownotes = _getShownotesContent();

    // Debug: Log the shownotes content
    if (widget.episode.description != null && widget.episode.description!.isNotEmpty) {
      final preview = widget.episode.description!.length > 100
          ? '${widget.episode.description!.substring(0, 100)}...'
          : widget.episode.description!;
      logger.AppLogger.debug('📝 [Shownotes] Description: $preview');
    } else {
      logger.AppLogger.debug('📝 [Shownotes] Description: NULL or EMPTY');
    }

    if (widget.episode.aiSummary != null && widget.episode.aiSummary!.isNotEmpty) {
      final preview = widget.episode.aiSummary!.length > 100
          ? '${widget.episode.aiSummary!.substring(0, 100)}...'
          : widget.episode.aiSummary!;
      logger.AppLogger.debug('📝 [Shownotes] AI Summary: $preview');
    } else {
      logger.AppLogger.debug('📝 [Shownotes] AI Summary: NULL or EMPTY');
    }

    logger.AppLogger.debug('📝 [Shownotes] Metadata shownotes: ${widget.episode.metadata?['shownotes']}');
    logger.AppLogger.debug('📝 [Shownotes] Final content length: ${shownotes.length}');

    if (shownotes.isEmpty) {
      logger.AppLogger.debug('📝 [Shownotes] No content found, showing empty state');
      return _buildEmptyState(context);
    }

    // Sanitize HTML to prevent XSS attacks
    final sanitizedHtml = HtmlSanitizer.sanitize(shownotes);
    logger.AppLogger.debug('📝 [Shownotes] Sanitized HTML length: ${sanitizedHtml.length}');

    return Container(
      padding: const EdgeInsets.all(16),
      child: SingleChildScrollView(
        controller: _scrollController,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Shownotes header
            Text(
              'Shownotes',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: Theme.of(context).colorScheme.onSurface,
              ),
            ),
            const SizedBox(height: 12),

            // HTML content with text selection support
            SelectionArea(
              child: HtmlWidget(
                sanitizedHtml,
                // Material 3 styling
                textStyle: Theme.of(context).textTheme.bodyLarge?.copyWith(
                  fontSize: 15,
                  height: 1.6,
                  color: Theme.of(context).colorScheme.onSurface,
                ),
                // Handle link taps
                onTapUrl: (url) async {
                  try {
                    final uri = Uri.parse(url);
                    if (await canLaunchUrl(uri)) {
                      await launchUrl(
                        uri,
                        mode: LaunchMode.externalApplication,
                      );
                      return true;
                    }
                    return false;
                  } catch (e) {
                    if (context.mounted) {
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text('Error opening link: ${e.toString()}'),
                          backgroundColor: Theme.of(context).colorScheme.error,
                        ),
                      );
                    }
                    return false;
                  }
                },
                // Handle errors gracefully
                onErrorBuilder: (context, error, stackTrace) {
                  return Container(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                      children: [
                        Icon(
                          Icons.error_outline,
                          color: Theme.of(context).colorScheme.error,
                        ),
                        const SizedBox(height: 8),
                        Text(
                          'Failed to render shownotes',
                          style: TextStyle(
                            color: Theme.of(context).colorScheme.error,
                          ),
                        ),
                      ],
                    ),
                  );
                },
                // Custom styling for HTML elements
                customStylesBuilder: (element) {
                  // Add custom styling for specific elements
                  final styles = <String, String>{};

                  // Blockquote styling
                  if (element.localName == 'blockquote') {
                    styles['border-left'] = '4px solid ${_colorToHex(Theme.of(context).colorScheme.primary)}';
                    styles['padding-left'] = '16px';
                    styles['margin-left'] = '0';
                    styles['color'] = _colorToHex(Theme.of(context).colorScheme.onSurfaceVariant);
                  }

                  // Code block styling
                  if (element.localName == 'pre' || element.localName == 'code') {
                    styles['background-color'] = _colorToHex(Theme.of(context).colorScheme.surfaceContainerHighest);
                    styles['padding'] = '8px';
                    styles['border-radius'] = '4px';
                    styles['font-family'] = 'monospace';
                  }

                  // Heading styling
                  if (element.localName?.startsWith('h') == true) {
                    styles['color'] = _colorToHex(Theme.of(context).colorScheme.onSurface);
                    styles['font-weight'] = 'bold';
                  }

                  // Link styling
                  if (element.localName == 'a') {
                    styles['color'] = _colorToHex(Theme.of(context).colorScheme.primary);
                    styles['text-decoration'] = 'underline';
                  }

                  return styles.isNotEmpty ? styles : null;
                },
                // Enable selection for text
                enableCaching: true,
                // Build mode for better performance
                renderMode: RenderMode.column,
              ),
            ),
          ],
        ),
      ),
    );
  }

  String _getShownotesContent() {
    // Priority:
    // 1. Episode description (Most accurate for shownotes)
    // 2. Episode AI summary
    // 3. Metadata
    // 4. Subscription description (Fallback)

    // 1. Try to get episode description first
    if (widget.episode.description?.isNotEmpty == true) {
      return widget.episode.description!;
    }

    // 2. Fallback to episode AI summary
    if (widget.episode.aiSummary?.isNotEmpty == true) {
      return widget.episode.aiSummary!;
    }

    // 3. Try to get from metadata
    if (widget.episode.metadata != null && widget.episode.metadata!['shownotes'] != null) {
      return widget.episode.metadata!['shownotes'].toString();
    }

    // 4. Fallback to subscription description
    if (widget.episode.subscription != null) {
      final subscriptionDesc = widget.episode.subscription!['description'];
      if (subscriptionDesc != null && subscriptionDesc.toString().isNotEmpty) {
        return subscriptionDesc.toString();
      }
    }

    return '';
  }

  Widget _buildEmptyState(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.description_outlined,
            size: 64,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          const SizedBox(height: 16),
          Text(
            l10n.podcast_no_shownotes,
            style: TextStyle(
              fontSize: 16,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }

  // Helper method to convert Color to hex string
  String _colorToHex(Color color) {
    return '#${color.toARGB32().toRadixString(16).substring(2)}';
  }
}
