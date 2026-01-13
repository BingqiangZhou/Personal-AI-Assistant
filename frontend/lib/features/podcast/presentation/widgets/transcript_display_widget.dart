import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../providers/transcription_providers.dart';
import '../../data/models/podcast_transcription_model.dart';

class TranscriptDisplayWidget extends ConsumerStatefulWidget {
  final int episodeId;
  final PodcastTranscriptionResponse? transcription;
  final Function(String)? onSearchChanged;

  const TranscriptDisplayWidget({
    super.key,
    required this.episodeId,
    this.transcription,
    this.onSearchChanged,
  });

  @override
  ConsumerState<TranscriptDisplayWidget> createState() => TranscriptDisplayWidgetState();
}

class TranscriptDisplayWidgetState extends ConsumerState<TranscriptDisplayWidget> {
  final TextEditingController _searchController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  List<String> _searchResults = [];
  bool _isSearching = false;

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
  void initState() {
    super.initState();
    _searchController.addListener(_onSearchChanged);
  }

  @override
  void dispose() {
    _searchController.removeListener(_onSearchChanged);
    _searchController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  void _onSearchChanged() {
    final query = _searchController.text;
    if (query.isNotEmpty) {
      setState(() {
        _isSearching = true;
      });
      _performSearch(query);
    } else {
      setState(() {
        _isSearching = false;
        _searchResults.clear();
      });
    }
    widget.onSearchChanged?.call(query);
  }

  void _performSearch(String query) {
    final content = getTranscriptionText(widget.transcription) ?? '';
    searchTranscript(ref, content, query);

    // Get search results from provider
    final results = ref.read(transcriptionSearchResultsProvider);
    setState(() {
      _searchResults = results;
    });
  }

  void _clearSearch() {
    _searchController.clear();
    setState(() {
      _isSearching = false;
      _searchResults.clear();
    });
    clearTranscriptionSearchQuery(ref);
  }

  @override
  Widget build(BuildContext context) {
    final content = getTranscriptionText(widget.transcription);

    if (content == null || content.isEmpty) {
      return _buildEmptyState(context);
    }

    return Column(
      children: [
        // Search bar
        _buildSearchBar(context),

        // Content
        Expanded(
          child: _isSearching ? _buildSearchResults(context) : _buildFullTranscript(context, content),
        ),
      ],
    );
  }

  Widget _buildSearchBar(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        border: Border(
          bottom: BorderSide(
            color: Theme.of(context).colorScheme.outlineVariant,
            width: 1,
          ),
        ),
      ),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: _searchController,
              decoration: InputDecoration(
                hintText: l10n.podcast_transcript_search_hint,
                prefixIcon: const Icon(Icons.search),
                suffixIcon: _isSearching
                    ? IconButton(
                        icon: const Icon(Icons.clear),
                        onPressed: _clearSearch,
                      )
                    : null,
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(28),
                  borderSide: BorderSide(
                    color: Theme.of(context).colorScheme.outline,
                  ),
                ),
                enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(28),
                  borderSide: BorderSide(
                    color: Theme.of(context).colorScheme.outline,
                  ),
                ),
                focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(28),
                  borderSide: BorderSide(
                    color: Theme.of(context).colorScheme.primary,
                    width: 2,
                  ),
                ),
                contentPadding: const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 12,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFullTranscript(BuildContext context, String content) {
    // 根据句号分段（支持中英文句号）
    final segments = _splitIntoSentences(content);

    return Container(
      padding: const EdgeInsets.all(16),
      child: ListView.separated(
        controller: _scrollController,
        itemCount: segments.length,
        separatorBuilder: (context, index) => const SizedBox(height: 12),
        itemBuilder: (context, index) {
          return _buildSentenceSegment(context, segments[index], index);
        },
      ),
    );
  }

  /// 将文本根据句号分段（支持中英文句号）
  List<String> _splitIntoSentences(String text) {
    final segments = <String>[];

    // 使用正则表达式按句号分段，支持：
    // - 中文句号 。
    // - 英文句号 .
    // - 问号 ?
    // - 感叹号 ！!
    // - 省略号 ......
    final sentencePattern = RegExp(r'[^。.！!？?]+[。.！!？?]+[^。.！!？?]*');

    final matches = sentencePattern.allMatches(text);

    for (final match in matches) {
      final sentence = match.group(0)?.trim();
      if (sentence != null && sentence.isNotEmpty) {
        segments.add(sentence);
      }
    }

    // 如果没有匹配到任何句子，返回原文本
    if (segments.isEmpty) {
      return [text];
    }

    return segments;
  }

  Widget _buildSentenceSegment(BuildContext context, String sentence, int index) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.2),
          width: 1,
        ),
      ),
      child: SelectableText(
        sentence,
        style: TextStyle(
          fontSize: 15,
          height: 1.6,
          color: Theme.of(context).colorScheme.onSurface,
        ),
      ),
    );
  }

  Widget _buildSearchResults(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    if (_searchResults.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.search_off,
              size: 64,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            const SizedBox(height: 16),
            Text(
              l10n.podcast_transcript_no_match,
              style: TextStyle(
                fontSize: 16,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      );
    }

    return Container(
      padding: const EdgeInsets.all(16),
      child: ListView.builder(
        controller: _scrollController,
        itemCount: _searchResults.length,
        itemBuilder: (context, index) {
          final result = _searchResults[index];
          return _buildSearchResultItem(context, result, index);
        },
      ),
    );
  }

  Widget _buildSearchResultItem(BuildContext context, String result, int index) {
    final l10n = AppLocalizations.of(context)!;
    final query = _searchController.text;
    final highlightedText = _highlightSearchText(result, query);

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.2),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Result number
          Text(
            l10n.podcast_transcript_match(index + 1),
            style: TextStyle(
              fontSize: 12,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w500,
            ),
          ),
          const SizedBox(height: 4),
          // Highlighted text
          RichText(
            text: highlightedText,
          ),
        ],
      ),
    );
  }

  TextSpan _highlightSearchText(String text, String query) {
    if (query.isEmpty) {
      return TextSpan(
        text: text,
        style: TextStyle(
          fontSize: 15,
          height: 1.6,
          color: Theme.of(context).colorScheme.onSurface,
        ),
      );
    }

    final spans = <TextSpan>[];
    final lowerText = text.toLowerCase();
    final lowerQuery = query.toLowerCase();
    int start = 0;

    while (true) {
      final index = lowerText.indexOf(lowerQuery, start);
      if (index == -1) break;

      // Add text before match
      if (index > start) {
        spans.add(TextSpan(
          text: text.substring(start, index),
          style: TextStyle(
            fontSize: 15,
            height: 1.6,
            color: Theme.of(context).colorScheme.onSurface,
          ),
        ));
      }

      // Add highlighted match
      spans.add(TextSpan(
        text: text.substring(index, index + query.length),
        style: TextStyle(
          fontSize: 15,
          height: 1.6,
          color: Theme.of(context).colorScheme.primary,
          fontWeight: FontWeight.bold,
          backgroundColor: Theme.of(context).colorScheme.primary.withValues(alpha: 0.2),
        ),
      ));

      start = index + query.length;
    }

    // Add remaining text
    if (start < text.length) {
      spans.add(TextSpan(
        text: text.substring(start),
        style: TextStyle(
          fontSize: 15,
          height: 1.6,
          color: Theme.of(context).colorScheme.onSurface,
        ),
      ));
    }

    return TextSpan(children: spans);
  }

  Widget _buildEmptyState(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.article_outlined,
            size: 64,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          const SizedBox(height: 16),
          Text(
            l10n.podcast_no_transcript,
            style: TextStyle(
              fontSize: 16,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            l10n.podcast_click_to_transcribe,
            style: TextStyle(
              fontSize: 14,
              color: Theme.of(context).colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
            ),
          ),
        ],
      ),
    );
  }
}

/// Widget for displaying formatted transcription with speaker labels and timestamps
class FormattedTranscriptWidget extends ConsumerWidget {
  final PodcastTranscriptionResponse? transcription;

  const FormattedTranscriptWidget({
    super.key,
    this.transcription,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final content = getTranscriptionText(transcription);

    if (content == null || content.isEmpty) {
      return const TranscriptDisplayWidget(transcription: null, episodeId: 0);
    }

    // Try to parse the transcript for dialogue format
    final segments = _parseTranscriptSegments(content);

    if (segments.isEmpty) {
      // Fall back to plain text display
      return TranscriptDisplayWidget(transcription: transcription, episodeId: 0);
    }

    return Container(
      padding: const EdgeInsets.all(16),
      child: ListView.builder(
        itemCount: segments.length,
        itemBuilder: (context, index) {
          final segment = segments[index];
          return _buildDialogueSegment(context, segment);
        },
      ),
    );
  }

  List<TranscriptDialogueSegment> _parseTranscriptSegments(String content) {
    final segments = <TranscriptDialogueSegment>[];
    final lines = content.split('\n');

    for (var line in lines) {
      final trimmedLine = line.trim();
      if (trimmedLine.isEmpty) continue;

      // Try to match dialogue patterns
      // Pattern: [Speaker] Text
      final speakerMatch = RegExp(r'^\[([^\]]+)\]\s*(.*)$').firstMatch(trimmedLine);
      if (speakerMatch != null) {
        segments.add(TranscriptDialogueSegment(
          speaker: speakerMatch.group(1),
          text: speakerMatch.group(2) ?? '',
        ));
        continue;
      }

      // Pattern: Speaker: Text
      final colonMatch = RegExp(r'^([^:]+):\s*(.*)$').firstMatch(trimmedLine);
      if (colonMatch != null) {
        segments.add(TranscriptDialogueSegment(
          speaker: colonMatch.group(1),
          text: colonMatch.group(2) ?? '',
        ));
        continue;
      }

      // Pattern: [HH:MM:SS] Text
      final timestampMatch = RegExp(r'^\[(\d{1,2}:\d{2}(?::\d{2})?)\]\s*(.*)$').firstMatch(trimmedLine);
      if (timestampMatch != null) {
        segments.add(TranscriptDialogueSegment(
          timestamp: timestampMatch.group(1),
          text: timestampMatch.group(2) ?? '',
        ));
        continue;
      }

      // Default: just text
      segments.add(TranscriptDialogueSegment(text: trimmedLine));
    }

    return segments;
  }

  Widget _buildDialogueSegment(BuildContext context, TranscriptDialogueSegment segment) {
    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header with speaker/timestamp
          if (segment.speaker != null || segment.timestamp != null)
            Row(
              children: [
                if (segment.speaker != null)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
                      borderRadius: BorderRadius.circular(4),
                      border: Border.all(
                        color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
                        width: 1,
                      ),
                    ),
                    child: Text(
                      segment.speaker!,
                      style: TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                        color: Theme.of(context).colorScheme.primary,
                      ),
                    ),
                  ),
                if (segment.speaker != null && segment.timestamp != null)
                  const SizedBox(width: 8),
                if (segment.timestamp != null)
                  Text(
                    segment.timestamp!,
                    style: TextStyle(
                      fontSize: 11,
                      color: Theme.of(context).colorScheme.onSurfaceVariant.withValues(alpha: 0.6),
                    ),
                  ),
              ],
            ),
          if (segment.speaker != null || segment.timestamp != null)
            const SizedBox(height: 6),
          // Text content
          SelectableText(
            segment.text,
            style: TextStyle(
              fontSize: 15,
              height: 1.6,
              color: Theme.of(context).colorScheme.onSurface,
            ),
          ),
        ],
      ),
    );
  }
}