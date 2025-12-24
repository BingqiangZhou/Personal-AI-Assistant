import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../data/models/podcast_episode_model.dart';

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

    if (shownotes.isEmpty) {
      return _buildEmptyState(context);
    }

    return Container(
      padding: const EdgeInsets.all(16),
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Shownotes content - 节目描述自适应整个宽度
            _buildShownotesContent(context, shownotes),
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

  Widget _buildShownotesContent(BuildContext context, String content) {
    // Parse for rich text elements
    final segments = _parseRichText(content);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Shownotes',
          style: TextStyle(
            fontSize: 18,
            fontWeight: FontWeight.bold,
            color: Theme.of(context).colorScheme.onSurface,
          ),
        ),
        const SizedBox(height: 12),
        ...segments.map((segment) => _buildTextSegment(context, segment)),
      ],
    );
  }

  List<RichTextSegment> _parseRichText(String content) {
    final segments = <RichTextSegment>[];
    final lines = content.split('\n');

    for (var line in lines) {
      final trimmedLine = line.trim();

      // Skip empty lines
      if (trimmedLine.isEmpty) {
        segments.add(RichTextSegment(type: RichTextType.lineBreak, text: ''));
        continue;
      }

      // Check for headings
      if (trimmedLine.startsWith('# ')) {
        segments.add(RichTextSegment(
          type: RichTextType.heading,
          text: trimmedLine.substring(2),
        ));
        continue;
      }

      if (trimmedLine.startsWith('## ')) {
        segments.add(RichTextSegment(
          type: RichTextType.subheading,
          text: trimmedLine.substring(3),
        ));
        continue;
      }

      // Check for lists
      if (trimmedLine.startsWith(RegExp(r'^\d+\.\s'))) {
        segments.add(RichTextSegment(
          type: RichTextType.orderedListItem,
          text: trimmedLine.replaceFirst(RegExp(r'^\d+\.\s'), ''),
        ));
        continue;
      }

      if (trimmedLine.startsWith(RegExp(r'^[-*•]\s'))) {
        segments.add(RichTextSegment(
          type: RichTextType.unorderedListItem,
          text: trimmedLine.substring(2),
        ));
        continue;
      }

      // Check for URLs
      final urlMatch = RegExp(r'(https?://[^\s]+)').firstMatch(trimmedLine);
      if (urlMatch != null) {
        final url = urlMatch.group(0)!;
        final beforeUrl = trimmedLine.substring(0, urlMatch.start);
        final afterUrl = trimmedLine.substring(urlMatch.end);

        if (beforeUrl.isNotEmpty) {
          segments.add(RichTextSegment(
            type: RichTextType.paragraph,
            text: beforeUrl,
          ));
        }

        segments.add(RichTextSegment(
          type: RichTextType.link,
          text: url,
          url: url,
        ));

        if (afterUrl.isNotEmpty) {
          segments.add(RichTextSegment(
            type: RichTextType.paragraph,
            text: afterUrl,
          ));
        }
        continue;
      }

      // Default to paragraph
      segments.add(RichTextSegment(
        type: RichTextType.paragraph,
        text: trimmedLine,
      ));
    }

    return segments;
  }

  Widget _buildTextSegment(BuildContext context, RichTextSegment segment) {
    switch (segment.type) {
      case RichTextType.heading:
        return Padding(
          padding: const EdgeInsets.symmetric(vertical: 16),
          child: Text(
            segment.text,
            style: TextStyle(
              fontSize: 20,
              fontWeight: FontWeight.bold,
              color: Theme.of(context).colorScheme.onSurface,
            ),
          ),
        );

      case RichTextType.subheading:
        return Padding(
          padding: const EdgeInsets.only(top: 16, bottom: 8),
          child: Text(
            segment.text,
            style: TextStyle(
              fontSize: 16,
              fontWeight: FontWeight.w600,
              color: Theme.of(context).colorScheme.onSurface,
            ),
          ),
        );

      case RichTextType.paragraph:
        return Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: SelectableText(
            segment.text,
            style: TextStyle(
              fontSize: 15,
              height: 1.6,
              color: Theme.of(context).colorScheme.onSurface,
            ),
          ),
        );

      case RichTextType.orderedListItem:
        return Padding(
          padding: const EdgeInsets.only(left: 24, bottom: 4),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                width: 20,
                child: Text(
                  '•',
                  style: TextStyle(
                    fontSize: 15,
                    height: 1.6,
                    color: Theme.of(context).colorScheme.onSurface,
                  ),
                ),
              ),
              Expanded(
                child: SelectableText(
                  segment.text,
                  style: TextStyle(
                    fontSize: 15,
                    height: 1.6,
                    color: Theme.of(context).colorScheme.onSurface,
                  ),
                ),
              ),
            ],
          ),
        );

      case RichTextType.unorderedListItem:
        return Padding(
          padding: const EdgeInsets.only(left: 24, bottom: 4),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                width: 20,
                child: Text(
                  '•',
                  style: TextStyle(
                    fontSize: 15,
                    height: 1.6,
                    color: Theme.of(context).colorScheme.onSurface,
                  ),
                ),
              ),
              Expanded(
                child: SelectableText(
                  segment.text,
                  style: TextStyle(
                    fontSize: 15,
                    height: 1.6,
                    color: Theme.of(context).colorScheme.onSurface,
                  ),
                ),
              ),
            ],
          ),
        );

      case RichTextType.link:
        return Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: InkWell(
            onTap: () => _launchUrl(segment.url!),
            borderRadius: BorderRadius.circular(4),
            child: Text(
              segment.text,
              style: TextStyle(
                fontSize: 15,
                height: 1.6,
                color: Theme.of(context).colorScheme.primary,
                decoration: TextDecoration.underline,
              ),
            ),
          ),
        );

      case RichTextType.lineBreak:
        return const SizedBox(height: 8);
    }
  }

  Widget _buildEmptyState(BuildContext context) {
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
            '暂无节目简介',
            style: TextStyle(
              fontSize: 16,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }

  String _formatDate(DateTime date) {
    final year = date.year;
    final month = date.month.toString().padLeft(2, '0');
    final day = date.day.toString().padLeft(2, '0');
    return '$year年$month月$day日';
  }

  Future<void> _launchUrl(String url) async {
    final uri = Uri.parse(url);
    if (await canLaunchUrl(uri)) {
      await launchUrl(
        uri,
        mode: LaunchMode.externalApplication,
      );
    }
  }
}

enum RichTextType {
  heading,
  subheading,
  paragraph,
  orderedListItem,
  unorderedListItem,
  link,
  lineBreak,
}

class RichTextSegment {
  final RichTextType type;
  final String text;
  final String? url;

  RichTextSegment({
    required this.type,
    required this.text,
    this.url,
  });
}