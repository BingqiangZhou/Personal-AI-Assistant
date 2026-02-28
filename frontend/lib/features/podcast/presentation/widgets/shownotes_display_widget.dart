import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_widget_from_html/flutter_widget_from_html.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/utils/app_logger.dart' as logger;
import '../../../../core/widgets/top_floating_notice.dart';
import '../../core/utils/html_sanitizer.dart';
import '../../data/models/podcast_episode_model.dart';

class ShownotesDisplayWidget extends ConsumerStatefulWidget {
  final PodcastEpisodeDetailResponse episode;

  const ShownotesDisplayWidget({super.key, required this.episode});

  @override
  ConsumerState<ShownotesDisplayWidget> createState() =>
      ShownotesDisplayWidgetState();
}

class ShownotesDisplayWidgetState
    extends ConsumerState<ShownotesDisplayWidget> {
  final ScrollController _scrollController = ScrollController();
  String _shownotes = '';
  String _sanitizedShownotes = '';

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
  void initState() {
    super.initState();
    _refreshShownotesCache(shouldSetState: false);
  }

  @override
  void didUpdateWidget(covariant ShownotesDisplayWidget oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (_contentSignature(oldWidget.episode) !=
        _contentSignature(widget.episode)) {
      _refreshShownotesCache(shouldSetState: true);
    }
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (_shownotes.isEmpty) {
      return _buildEmptyState(context);
    }

    return Container(
      padding: const EdgeInsets.all(16),
      child: SingleChildScrollView(
        controller: _scrollController,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Shownotes',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: Theme.of(context).colorScheme.onSurface,
                fontFamily: Theme.of(context).textTheme.titleLarge?.fontFamily,
                fontFamilyFallback: Theme.of(
                  context,
                ).textTheme.titleLarge?.fontFamilyFallback,
              ),
            ),
            const SizedBox(height: 12),
            SelectionArea(
              child: HtmlWidget(
                _sanitizedShownotes,
                textStyle: Theme.of(context).textTheme.bodyLarge?.copyWith(
                  fontSize: 15,
                  height: 1.6,
                  color: Theme.of(context).colorScheme.onSurface,
                ),
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
                      final l10n = AppLocalizations.of(context)!;
                      showTopFloatingNotice(
                        context,
                        message: l10n.error_opening_link(e.toString()),
                        isError: true,
                      );
                    }
                    return false;
                  }
                },
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
                customStylesBuilder: (element) {
                  final styles = <String, String>{};

                  if (element.localName == 'blockquote') {
                    styles['border-left'] =
                        '4px solid ${_colorToHex(Theme.of(context).colorScheme.primary)}';
                    styles['padding-left'] = '16px';
                    styles['margin-left'] = '0';
                    styles['color'] = _colorToHex(
                      Theme.of(context).colorScheme.onSurfaceVariant,
                    );
                  }

                  if (element.localName == 'pre' ||
                      element.localName == 'code') {
                    styles['background-color'] = _colorToHex(
                      Theme.of(context).colorScheme.surfaceContainerHighest,
                    );
                    styles['padding'] = '8px';
                    styles['border-radius'] = '4px';
                    styles['font-family'] = 'monospace';
                  }

                  if (element.localName?.startsWith('h') == true) {
                    styles['color'] = _colorToHex(
                      Theme.of(context).colorScheme.onSurface,
                    );
                    styles['font-weight'] = 'bold';
                  }

                  if (element.localName == 'a') {
                    styles['color'] = _colorToHex(
                      Theme.of(context).colorScheme.primary,
                    );
                    styles['text-decoration'] = 'underline';
                  }

                  return styles.isNotEmpty ? styles : null;
                },
                enableCaching: true,
                renderMode: RenderMode.column,
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _refreshShownotesCache({required bool shouldSetState}) {
    final nextShownotes = _resolveShownotesContent(widget.episode);
    final nextSanitized = nextShownotes.isEmpty
        ? ''
        : HtmlSanitizer.sanitize(nextShownotes);
    if (nextShownotes == _shownotes && nextSanitized == _sanitizedShownotes) {
      return;
    }

    if (kDebugMode) {
      logger.AppLogger.debug(
        '[Shownotes] content=${nextShownotes.length}, sanitized=${nextSanitized.length}',
      );
    }

    if (shouldSetState) {
      setState(() {
        _shownotes = nextShownotes;
        _sanitizedShownotes = nextSanitized;
      });
      return;
    }

    _shownotes = nextShownotes;
    _sanitizedShownotes = nextSanitized;
  }

  String _resolveShownotesContent(PodcastEpisodeDetailResponse episode) {
    if (episode.description?.isNotEmpty == true) {
      return episode.description!;
    }

    if (episode.aiSummary?.isNotEmpty == true) {
      return episode.aiSummary!;
    }

    if (episode.metadata != null && episode.metadata!['shownotes'] != null) {
      return episode.metadata!['shownotes'].toString();
    }

    if (episode.subscription != null) {
      final subscriptionDesc = episode.subscription!['description'];
      if (subscriptionDesc != null && subscriptionDesc.toString().isNotEmpty) {
        return subscriptionDesc.toString();
      }
    }

    return '';
  }

  String _contentSignature(PodcastEpisodeDetailResponse episode) {
    return '${episode.description}|${episode.aiSummary}|${episode.metadata?['shownotes']}|${episode.subscription?['description']}';
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

  String _colorToHex(Color color) {
    return '#${color.toARGB32().toRadixString(16).substring(2)}';
  }
}
