class SummarySanitizer {
  const SummarySanitizer._();

  /// Remove model reasoning tags while preserving normal markdown content.
  static String clean(String? input) {
    if (input == null || input.isEmpty) {
      return '';
    }

    var cleaned = input;
    final patterns = <RegExp>[
      RegExp(r'<thinking>.*?</thinking>', caseSensitive: false, dotAll: true),
      RegExp(r'<think>.*?</think>', caseSensitive: false, dotAll: true),
    ];

    for (final pattern in patterns) {
      cleaned = cleaned.replaceAll(pattern, '');
    }

    return cleaned.trim();
  }
}
