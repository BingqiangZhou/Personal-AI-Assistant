import 'package:html/parser.dart' as html_parser;

/// Cache entry with timestamp for expiry.
class _Entry<T> {
  _Entry(this.value) : createdAt = DateTime.now();
  final T value;
  final DateTime createdAt;
}

/// Cached HTML-to-plain-text conversion and sentence splitting.
class TextProcessingCache {
  static final _descriptionCache = <String, _Entry<String>>{};
  static final _sentenceCache = <String, _Entry<String>>{};
  static const _maxCacheSize = 100;
  static const _entryTtl = Duration(minutes: 30);

  /// Generic cache-through helper: returns cached value if fresh, otherwise
  /// computes via [compute], evicts the oldest entry if at capacity, stores
  /// the result, and returns it.
  static T _withCache<T>(String key, Map<String, _Entry<T>> cache, T Function() compute) {
    final cached = cache[key];
    if (cached != null && DateTime.now().difference(cached.createdAt) < _entryTtl) {
      return cached.value;
    }
    final result = compute();
    if (cache.length >= _maxCacheSize) cache.remove(cache.keys.first);
    cache[key] = _Entry(result);
    return result;
  }

  /// Converts HTML to plain text and caches the result.
  static String getCachedDescription(String? rawDescription) {
    if (rawDescription == null || rawDescription.isEmpty) return '';
    return _withCache(rawDescription, _descriptionCache, () {
      final body = html_parser.parse(rawDescription).body;
      if (body == null) return '';
      // Insert newlines around block elements, collapse whitespace, trim.
      return body.text
          .replaceAll(RegExp(r'\s*\n\s*'), '\n')
          .replaceAll(RegExp(' {2,}'), ' ')
          .trim();
    });
  }

  /// Splits text into sentences and caches the result.
  static List<String> getCachedSentences(String text) {
    if (text.isEmpty) return [];
    // Stored as joined string for compact cache storage.
    final joined = _withCache(text, _sentenceCache, () {
      final matches = RegExp('[^。.！!？?]+[。.！!？?]')
          .allMatches(text)
          .map((m) => m.group(0)!.trim())
          .where((s) => s.isNotEmpty)
          .toList();
      return matches.isEmpty && text.trim().isNotEmpty
          ? text.trim()
          : matches.join('\x00');
    });
    return joined.split('\x00');
  }

  /// Clears all caches. Used in tests.
  static void clearAll() {
    _descriptionCache.clear();
    _sentenceCache.clear();
  }
}
