import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:flutter_widget_from_html/flutter_widget_from_html.dart';
import '../../../../core/localization/app_localizations.dart';

import '../../data/models/podcast_episode_model.dart';
import '../../core/utils/html_sanitizer.dart';

class ShownotesDisplayWidget extends ConsumerWidget {
  final PodcastEpisodeDetailResponse episode;

  const ShownotesDisplayWidget({
    super.key,
    required this.episode,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Try to get shownotes from different sources
    final shownotes = _getShownotesContent();

    // Debug: Log the shownotes content
    if (episode.description != null && episode.description!.isNotEmpty) {
      final preview = episode.description!.length > 100
          ? '${episode.description!.substring(0, 100)}...'
          : episode.description!;
      debugPrint('📝 [Shownotes] Description: $preview');
    } else {
      debugPrint('📝 [Shownotes] Description: NULL or EMPTY');
    }

    if (episode.aiSummary != null && episode.aiSummary!.isNotEmpty) {
      final preview = episode.aiSummary!.length > 100
          ? '${episode.aiSummary!.substring(0, 100)}...'
          : episode.aiSummary!;
      debugPrint('📝 [Shownotes] AI Summary: $preview');
    } else {
      debugPrint('📝 [Shownotes] AI Summary: NULL or EMPTY');
    }

    debugPrint('📝 [Shownotes] Metadata shownotes: ${episode.metadata?['shownotes']}');
    debugPrint('📝 [Shownotes] Final content length: ${shownotes.length}');

    if (shownotes.isEmpty) {
      debugPrint('📝 [Shownotes] No content found, showing empty state');
      return _buildEmptyState(context);
    }

    // Sanitize HTML to prevent XSS attacks
    final sanitizedHtml = HtmlSanitizer.sanitize(shownotes);
    debugPrint('📝 [Shownotes] Sanitized HTML length: ${sanitizedHtml.length}');

    return LayoutBuilder(
      builder: (context, constraints) {
        // Responsive padding based on screen width
        final isDesktop = constraints.maxWidth > 840;
        final isTablet = constraints.maxWidth > 600;

        final horizontalPadding = isDesktop ? 32.0 : (isTablet ? 24.0 : 16.0);
        final maxContentWidth = isDesktop ? 800.0 : double.infinity;

        return Container(
          padding: EdgeInsets.symmetric(horizontal: horizontalPadding, vertical: 16),
          child: SingleChildScrollView(
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

                // HTML content with responsive constraints
                Container(
                  constraints: BoxConstraints(maxWidth: maxContentWidth),
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
                        styles['border-left'] = '4px solid ${Theme.of(context).colorScheme.primary.toHex()}';
                        styles['padding-left'] = '16px';
                        styles['margin-left'] = '0';
                        styles['color'] = Theme.of(context).colorScheme.onSurfaceVariant.toHex();
                      }

                      // Code block styling
                      if (element.localName == 'pre' || element.localName == 'code') {
                        styles['background-color'] = Theme.of(context).colorScheme.surfaceContainerHighest.toHex();
                        styles['padding'] = '8px';
                        styles['border-radius'] = '4px';
                        styles['font-family'] = 'monospace';
                      }

                      // Heading styling
                      if (element.localName?.startsWith('h') == true) {
                        styles['color'] = Theme.of(context).colorScheme.onSurface.toHex();
                        styles['font-weight'] = 'bold';
                      }

                      // Link styling
                      if (element.localName == 'a') {
                        styles['color'] = Theme.of(context).colorScheme.primary.toHex();
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
      },
    );
  }

  String _getShownotesContent() {
    // Priority:
    // 1. Episode description (Most accurate for shownotes)
    // 2. Episode AI summary
    // 3. Metadata
    // 4. Subscription description (Fallback)

    // 1. Try to get episode description first
    if (episode.description?.isNotEmpty == true) {
      return episode.description!;
    }

    // 2. Fallback to episode AI summary
    if (episode.aiSummary?.isNotEmpty == true) {
      return episode.aiSummary!;
    }

    // 3. Try to get from metadata
    if (episode.metadata != null && episode.metadata!['shownotes'] != null) {
      return episode.metadata!['shownotes'].toString();
    }

    // 4. Fallback to subscription description
    if (episode.subscription != null) {
      final subscriptionDesc = episode.subscription!['description'];
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
}

/// Extension method to convert Color to hex string
extension ColorExtension on Color {
  String toHex() {
    return '#${toARGB32().toRadixString(16).substring(2)}';
  }
}

