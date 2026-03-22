/// Text processing cache utility class.
///
/// Uses LRU strategy to manage cache, avoiding repeated regex processing on each build.
/// This improves performance by caching expensive text processing operations.
class TextProcessingCache {
  static final _descriptionCache = <String, String>{};
  static final _sentenceCache = <String, List<String>>{};
  static const int _maxCacheSize = 200;

  /// Gets cached description text (HTML tags cleaned).
  ///
  /// Extracts processing logic from podcast_feed_page.dart's `_getFeedCardDescription`
  /// and related helper functions.
  static String getCachedDescription(String? rawDescription) {
    if (rawDescription == null || rawDescription.isEmpty) return '';

    final cacheKey = rawDescription.hashCode.toString();
    if (_descriptionCache.containsKey(cacheKey)) {
      return _descriptionCache[cacheKey]!;
    }

    final processed = _processDescription(rawDescription);

    // LRU eviction
    if (_descriptionCache.length >= _maxCacheSize) {
      _descriptionCache.remove(_descriptionCache.keys.first);
    }

    _descriptionCache[cacheKey] = processed;
    return processed;
  }

  /// Gets cached sentence list.
  ///
  /// Extracts processing logic from transcript_display_widget.dart's `_splitIntoSentences`.
  static List<String> getCachedSentences(String text) {
    if (text.isEmpty) return [];

    final cacheKey = text.hashCode.toString();
    if (_sentenceCache.containsKey(cacheKey)) {
      return _sentenceCache[cacheKey]!;
    }

    final sentences = _splitIntoSentences(text);

    if (_sentenceCache.length >= _maxCacheSize) {
      _sentenceCache.remove(_sentenceCache.keys.first);
    }

    _sentenceCache[cacheKey] = sentences;
    return sentences;
  }

  /// Processes description text by removing HTML tags and cleaning content.
  ///
  /// This logic is extracted from podcast_feed_page.dart:
  /// - `_getFeedCardDescription`
  /// - `_recoverMalformedTagInlineContent`
  /// - `_recoverMalformedTagLine`
  /// - `_removeLikelyCssNoise`
  static String _processDescription(String description) {
    final sanitized = description.replaceAll(
      RegExp(r'<br\s*/?>', caseSensitive: false),
      '\n',
    ).replaceAll(
      RegExp(r'</p\s*>', caseSensitive: false),
      '\n',
    ).replaceAll(
      RegExp(r'</div\s*>', caseSensitive: false),
      '\n',
    ).replaceAll(
      RegExp(r'</li\s*>', caseSensitive: false),
      '\n',
    ).replaceAll(
      RegExp(r'<[^>]*>'),
      '',
    );

    if (sanitized.isEmpty) {
      return '';
    }

    // Recover visible content when malformed/truncated tag fragments remain.
    final recovered = _recoverMalformedTagInlineContent(sanitized);
    final cleaned = recovered.replaceAll(
      RegExp(r'<[/!]?[a-zA-Z][^>\n]*(?=\n|$)'),
      '',
    );

    final cssCleaned = _removeLikelyCssNoise(cleaned);
    return cssCleaned.trim();
  }

  /// Splits text into sentences based on punctuation marks.
  ///
  /// Supports Chinese and English sentence delimiters:
  /// - Chinese period 。
  /// - English period .
  /// - Question marks ?？
  /// - Exclamation marks ！!
  static List<String> _splitIntoSentences(String text) {
    final segments = <String>[];

    // Use regex to split by sentence delimiters
    final sentencePattern = RegExp(r'[^。.！!？?]+[。.！!？?]+[^。.！!？?]*');

    final matches = sentencePattern.allMatches(text);

    for (final match in matches) {
      final sentence = match.group(0)?.trim();
      if (sentence != null && sentence.isNotEmpty) {
        segments.add(sentence);
      }
    }

    // If no sentences were matched, return original text
    if (segments.isEmpty) {
      return [text];
    }

    return segments;
  }

  /// Recovers content from malformed tag fragments at end of lines.
  ///
  /// Extracted from podcast_feed_page.dart's `_recoverMalformedTagInlineContent`.
  static String _recoverMalformedTagInlineContent(String text) {
    final lines = text.split('\n');
    final recoveredLines = lines.map(_recoverMalformedTagLine).toList();
    return recoveredLines.join('\n');
  }

  /// Recovers content from a single line with malformed tag.
  ///
  /// Extracted from podcast_feed_page.dart's `_recoverMalformedTagLine`.
  static String _recoverMalformedTagLine(String line) {
    final malformedTagMatch = RegExp(r'<[/!]?[a-zA-Z][^>]*$').firstMatch(line);
    if (malformedTagMatch == null) {
      return line;
    }

    final tagStart = malformedTagMatch.start;
    final prefix = line.substring(0, tagStart);
    final fragment = line.substring(tagStart);

    // If content is appended after a quoted attribute value, keep that tail.
    final lastDoubleQuote = fragment.lastIndexOf('"');
    final lastSingleQuote = fragment.lastIndexOf("'");
    final lastQuoteIndex = lastDoubleQuote > lastSingleQuote
        ? lastDoubleQuote
        : lastSingleQuote;

    if (lastQuoteIndex != -1 && lastQuoteIndex + 1 < fragment.length) {
      final tail = fragment.substring(lastQuoteIndex + 1).trimLeft();
      if (tail.isNotEmpty &&
          !RegExp(r'^[a-zA-Z_:-][\w:.-]*\s*=').hasMatch(tail)) {
        return '$prefix$tail';
      }
    }

    // Fallback for CJK text directly following malformed tag attributes.
    final cjkMatch = RegExp(r'[\u4E00-\u9FFF]').firstMatch(fragment);
    if (cjkMatch != null) {
      return '$prefix${fragment.substring(cjkMatch.start)}';
    }

    return prefix;
  }

  /// Removes likely CSS noise from text.
  ///
  /// Extracted from podcast_feed_page.dart's `_removeLikelyCssNoise`.
  static String _removeLikelyCssNoise(String text) {
    final lines = text.split('\n');
    final cleanedLines = <String>[];

    for (var line in lines) {
      // Drop leading runs of style declarations
      line = line.replaceFirst(
        RegExp(
          r'^\s*(?:(?:color|font-weight|font-size|line-height|font-family|hyphens|text-align|letter-spacing|word-spacing|white-space|word-break|overflow-wrap|text-indent|text-decoration|font-style|font-variant|font-stretch|font)\s*:\s*[^;\n]+;?\s*){2,}',
          caseSensitive: false,
        ),
        '',
      );

      // Remove inline attribute fragments if any survived.
      line = line.replaceAll(
        RegExp(
          r'''\b(?:data-[\w-]+|style)\s*=\s*["'][^"']*["']''',
          caseSensitive: false,
        ),
        '',
      );

      // Remove remaining standalone CSS declarations.
      line = line.replaceAll(
        RegExp(
          r'\b(?:color|font-weight|font-size|line-height|font-family|hyphens|text-align|letter-spacing|word-spacing|white-space|word-break|overflow-wrap|text-indent|text-decoration|font-style|font-variant|font-stretch|font)\s*:\s*[^;\n]+;?',
          caseSensitive: false,
        ),
        '',
      );

      line = line.replaceAll(RegExp(r'^[;,\s]+|[;,\s]+$'), '').trim();

      final isPureCssLine = RegExp(
        r'^(?:[a-z-]+\s*:[^;\n]+;?\s*)+$',
        caseSensitive: false,
      ).hasMatch(line);

      if (line.isNotEmpty && !isPureCssLine) {
        cleanedLines.add(line);
      }
    }

    return cleanedLines.join('\n');
  }

  /// Clears all caches.
  ///
  /// Useful for testing or memory management.
  static void clearAll() {
    _descriptionCache.clear();
    _sentenceCache.clear();
  }
}
