/// Normalizes server URLs by trimming whitespace, removing trailing slashes,
/// and stripping API version prefixes.
class UrlNormalizer {
  UrlNormalizer._();

  /// Trims whitespace and removes trailing slashes.
  static String trimTrailingSlashes(String url) {
    var normalized = url.trim();
    while (normalized.endsWith('/')) {
      normalized = normalized.substring(0, normalized.length - 1);
    }
    return normalized;
  }

  /// Strips `/api/vN` suffix if present (e.g. `/api/v1`).
  static String stripApiPrefix(String url) {
    var normalized = url;
    if (normalized.endsWith('/api/v1')) {
      normalized = normalized.substring(0, normalized.length - 7);
    }
    return normalized;
  }

  /// Full normalization: trim + strip slashes + strip API prefix.
  static String normalize(String url) {
    return stripApiPrefix(trimTrailingSlashes(url));
  }

  /// Ensures URL has a scheme (defaults to http://).
  static String ensureScheme(String url) {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      return 'http://$url';
    }
    return url;
  }
}
