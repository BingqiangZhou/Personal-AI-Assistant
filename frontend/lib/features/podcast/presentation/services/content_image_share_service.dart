import 'dart:async';
import 'dart:io';
import 'dart:math' as math;

import 'package:file_selector/file_selector.dart' as file_selector;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_markdown_plus/flutter_markdown_plus.dart';
import 'package:image_gallery_saver_plus/image_gallery_saver_plus.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:screenshot/screenshot.dart';
import 'package:share_plus/share_plus.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../data/models/podcast_conversation_model.dart';

const int kDefaultShareMaxChars = 10000;
const String kShareImagePrimaryFontFamily = 'SF Pro Text';
const List<String> kShareImageFontFallback = <String>[
  'PingFang SC',
  'Hiragino Sans GB',
  'Noto Sans CJK SC',
  'Microsoft YaHei',
  'Segoe UI',
  'Helvetica Neue',
  'Arial',
];
const String kShareImageCodeFontFamily = 'SFMono-Regular';
const List<String> kShareImageCodeFontFallback = <String>[
  'Menlo',
  'Consolas',
  'Monaco',
  'monospace',
];
const double kShareCardDesktopWidth = 900;
const double kShareCardMobileHorizontalMargin = 32;
const double kShareCardMobileMinWidth = 320;
const double kShareCardMobileMaxWidth = 430;
const double kShareCardMobileFallbackWidth = 390;
const double kShareImageMinPixelRatio = 1.0;
const double kShareImageMobilePixelBudget = 8000000;
const double kShareImageDesktopPixelBudget = 12000000;
const double kShareImageEstimatedBaseHeight = 220;
const double kShareImageEstimatedLineHeight = 26;

enum ShareContentType { summary, transcript, chat }

enum ShareImageRenderMode { plainText, markdown, conversation }

enum ShareImageExportBehavior { share, save, unsupported }

class ShareConversationItem {
  final String roleLabel;
  final String content;
  final bool isUser;

  const ShareConversationItem({
    required this.roleLabel,
    required this.content,
    required this.isUser,
  });

  ShareConversationItem copyWith({
    String? roleLabel,
    String? content,
    bool? isUser,
  }) {
    return ShareConversationItem(
      roleLabel: roleLabel ?? this.roleLabel,
      content: content ?? this.content,
      isUser: isUser ?? this.isUser,
    );
  }
}

class ShareImagePayload {
  final String episodeTitle;
  final ShareContentType contentType;
  final String content;
  final String? sourceLabel;
  final int maxChars;
  final ShareImageRenderMode renderMode;
  final List<ShareConversationItem> conversationItems;

  const ShareImagePayload({
    required this.episodeTitle,
    required this.contentType,
    required this.content,
    this.sourceLabel,
    this.maxChars = kDefaultShareMaxChars,
    this.renderMode = ShareImageRenderMode.plainText,
    this.conversationItems = const <ShareConversationItem>[],
  });
}

class ContentImageShareException implements Exception {
  final String message;

  const ContentImageShareException(this.message);

  @override
  String toString() => message;
}

String truncateShareContent({
  required String content,
  required int maxChars,
  required String truncatedSuffix,
}) {
  if (content.length <= maxChars) {
    return content;
  }
  return '${content.substring(0, maxChars)}\n\n$truncatedSuffix';
}

String extractMarkdownSelection({
  required String markdown,
  required String selectedText,
}) {
  final source = markdown.trim();
  final selected = selectedText.trim();
  if (source.isEmpty || selected.isEmpty) {
    return selected;
  }

  final lines = source.split('\n');
  final mapping = _buildMarkdownVisibleMapping(lines);
  final directRange = _findBestVisibleRange(
    haystack: mapping.visibleText,
    needle: selected,
    lineByVisibleChar: mapping.lineByVisibleChar,
  );
  if (directRange != null) {
    return _extractMarkdownBlockFromVisibleRange(
      lines: lines,
      mapping: mapping,
      visibleStart: directRange.start,
      visibleLength: directRange.length,
      fallback: selected,
    );
  }

  final collapsedVisible = _collapseWhitespaceWithMapping(mapping.visibleText);
  final collapsedSelected = _collapseWhitespaceWithMapping(selected);
  if (collapsedSelected.collapsedText.isEmpty) {
    return selected;
  }
  final collapsedRange = _findBestCollapsedVisibleRange(
    collapsedVisible: collapsedVisible,
    collapsedNeedle: collapsedSelected.collapsedText,
    lineByVisibleChar: mapping.lineByVisibleChar,
  );
  if (collapsedRange != null) {
    return _extractMarkdownBlockFromVisibleRange(
      lines: lines,
      mapping: mapping,
      visibleStart: collapsedRange.start,
      visibleLength: collapsedRange.length,
      fallback: selected,
    );
  }

  final compactVisible = _compactTextWithMapping(mapping.visibleText);
  final compactSelected = _compactTextWithMapping(selected).compactText;
  if (compactSelected.isNotEmpty) {
    final compactRange = _findBestCompactedVisibleRange(
      compactVisible: compactVisible,
      compactNeedle: compactSelected,
      lineByVisibleChar: mapping.lineByVisibleChar,
    );
    if (compactRange != null) {
      return _extractMarkdownBlockFromVisibleRange(
        lines: lines,
        mapping: mapping,
        visibleStart: compactRange.start,
        visibleLength: compactRange.length,
        fallback: selected,
      );
    }
  }

  final lineWindowRange = _findBestLineWindowMatch(
    lines: lines,
    selectedText: selected,
  );
  if (lineWindowRange == null) {
    return selected;
  }
  final expanded = _expandMarkdownLineRange(
    lines: lines,
    startLine: lineWindowRange.$1,
    endLine: lineWindowRange.$2,
  );
  final snippet = lines.sublist(expanded.$1, expanded.$2 + 1).join('\n').trim();
  return snippet.isNotEmpty ? snippet : selected;
}

_VisibleRange? _findBestVisibleRange({
  required String haystack,
  required String needle,
  required List<int> lineByVisibleChar,
}) {
  if (haystack.isEmpty || needle.isEmpty || needle.length > haystack.length) {
    return null;
  }

  _VisibleRange? best;
  var searchFrom = 0;
  while (searchFrom <= haystack.length - needle.length) {
    final matchStart = haystack.indexOf(needle, searchFrom);
    if (matchStart < 0) {
      break;
    }

    final candidate = _VisibleRange(start: matchStart, length: needle.length);
    if (_isBetterVisibleRange(
      candidate: candidate,
      current: best,
      lineByVisibleChar: lineByVisibleChar,
    )) {
      best = candidate;
    }

    searchFrom = matchStart + 1;
  }

  return best;
}

_VisibleRange? _findBestCompactedVisibleRange({
  required _CompactedTextMapping compactVisible,
  required String compactNeedle,
  required List<int> lineByVisibleChar,
}) {
  final compactHaystack = compactVisible.compactText;
  if (compactHaystack.isEmpty ||
      compactNeedle.isEmpty ||
      compactNeedle.length > compactHaystack.length) {
    return null;
  }

  _VisibleRange? best;
  var searchFrom = 0;
  while (searchFrom <= compactHaystack.length - compactNeedle.length) {
    final compactStart = compactHaystack.indexOf(compactNeedle, searchFrom);
    if (compactStart < 0) {
      break;
    }

    final visibleStart = compactVisible.originalIndices[compactStart];
    final visibleEnd =
        compactVisible.originalIndices[compactStart + compactNeedle.length - 1];
    final candidate = _VisibleRange(
      start: visibleStart,
      length: visibleEnd - visibleStart + 1,
    );

    if (_isBetterVisibleRange(
      candidate: candidate,
      current: best,
      lineByVisibleChar: lineByVisibleChar,
    )) {
      best = candidate;
    }

    searchFrom = compactStart + 1;
  }

  return best;
}

_VisibleRange? _findBestCollapsedVisibleRange({
  required _CollapsedTextMapping collapsedVisible,
  required String collapsedNeedle,
  required List<int> lineByVisibleChar,
}) {
  final collapsedHaystack = collapsedVisible.collapsedText;
  if (collapsedHaystack.isEmpty ||
      collapsedNeedle.isEmpty ||
      collapsedNeedle.length > collapsedHaystack.length) {
    return null;
  }

  _VisibleRange? best;
  var searchFrom = 0;
  while (searchFrom <= collapsedHaystack.length - collapsedNeedle.length) {
    final collapsedStart = collapsedHaystack.indexOf(
      collapsedNeedle,
      searchFrom,
    );
    if (collapsedStart < 0) {
      break;
    }

    final visibleStart = collapsedVisible.originalIndices[collapsedStart];
    final visibleEnd = collapsedVisible
        .originalIndices[collapsedStart + collapsedNeedle.length - 1];
    final candidate = _VisibleRange(
      start: visibleStart,
      length: visibleEnd - visibleStart + 1,
    );

    if (_isBetterVisibleRange(
      candidate: candidate,
      current: best,
      lineByVisibleChar: lineByVisibleChar,
    )) {
      best = candidate;
    }

    searchFrom = collapsedStart + 1;
  }

  return best;
}

bool _isBetterVisibleRange({
  required _VisibleRange candidate,
  required _VisibleRange? current,
  required List<int> lineByVisibleChar,
}) {
  if (candidate.start < 0 ||
      candidate.length <= 0 ||
      candidate.start + candidate.length > lineByVisibleChar.length) {
    return false;
  }
  if (current == null) {
    return true;
  }

  final candidateLineSpan = _lineSpanForVisibleRange(
    candidate,
    lineByVisibleChar,
  );
  final currentLineSpan = _lineSpanForVisibleRange(current, lineByVisibleChar);
  if (candidateLineSpan != currentLineSpan) {
    return candidateLineSpan < currentLineSpan;
  }
  if (candidate.length != current.length) {
    return candidate.length < current.length;
  }
  return candidate.start < current.start;
}

int _lineSpanForVisibleRange(_VisibleRange range, List<int> lineByVisibleChar) {
  final startLine = lineByVisibleChar[range.start];
  final endLine = lineByVisibleChar[range.start + range.length - 1];
  return endLine - startLine;
}

(int, int)? _findBestLineWindowMatch({
  required List<String> lines,
  required String selectedText,
}) {
  if (lines.isEmpty || selectedText.isEmpty) {
    return null;
  }

  final visibleLines = lines.map(_lineToVisibleText).toList(growable: false);
  final collapsedSelected = _collapseWhitespaceWithMapping(
    selectedText,
  ).collapsedText;
  final compactSelected = _compactTextWithMapping(selectedText).compactText;
  if (collapsedSelected.isEmpty) {
    return null;
  }

  (int, int)? best;
  for (var start = 0; start < visibleLines.length; start++) {
    final buffer = StringBuffer();
    for (var end = start; end < visibleLines.length; end++) {
      if (end > start) {
        buffer.write('\n');
      }
      buffer.write(visibleLines[end]);

      final visibleWindow = buffer.toString();
      final directMatch = visibleWindow.contains(selectedText);
      final collapsedWindow = _collapseWhitespaceWithMapping(
        visibleWindow,
      ).collapsedText;
      final compactWindow = _compactTextWithMapping(visibleWindow).compactText;
      final collapsedMatch = collapsedWindow.contains(collapsedSelected);
      final compactMatch =
          compactSelected.isNotEmpty && compactWindow.contains(compactSelected);
      if (!directMatch && !collapsedMatch && !compactMatch) {
        continue;
      }

      final candidate = (start, end);
      if (_isBetterLineRange(candidate: candidate, current: best)) {
        best = candidate;
      }
      break;
    }
  }
  return best;
}

bool _isBetterLineRange({
  required (int, int) candidate,
  required (int, int)? current,
}) {
  if (current == null) {
    return true;
  }
  final candidateSpan = candidate.$2 - candidate.$1;
  final currentSpan = current.$2 - current.$1;
  if (candidateSpan != currentSpan) {
    return candidateSpan < currentSpan;
  }
  return candidate.$1 < current.$1;
}

String _extractMarkdownBlockFromVisibleRange({
  required List<String> lines,
  required _MarkdownVisibleMapping mapping,
  required int visibleStart,
  required int visibleLength,
  required String fallback,
}) {
  if (visibleStart < 0 ||
      visibleLength <= 0 ||
      visibleStart + visibleLength > mapping.visibleText.length) {
    return fallback;
  }

  final startLine = mapping.lineByVisibleChar[visibleStart];
  final endLine = mapping.lineByVisibleChar[visibleStart + visibleLength - 1];
  if (startLine < 0 ||
      endLine < startLine ||
      startLine >= lines.length ||
      endLine >= lines.length) {
    return fallback;
  }

  final expanded = _expandMarkdownLineRange(
    lines: lines,
    startLine: startLine,
    endLine: endLine,
  );
  final snippet = lines.sublist(expanded.$1, expanded.$2 + 1).join('\n').trim();
  return snippet.isNotEmpty ? snippet : fallback;
}

_MarkdownVisibleMapping _buildMarkdownVisibleMapping(List<String> lines) {
  final visibleLines = <String>[];
  var inFence = false;

  for (final line in lines) {
    if (_isFenceLine(line)) {
      inFence = !inFence;
      visibleLines.add('');
      continue;
    }
    if (inFence) {
      visibleLines.add(line);
      continue;
    }
    visibleLines.add(_lineToVisibleText(line));
  }

  final visibleBuffer = StringBuffer();
  final lineByVisibleChar = <int>[];

  for (var i = 0; i < visibleLines.length; i++) {
    final visibleLine = visibleLines[i];
    for (var j = 0; j < visibleLine.length; j++) {
      visibleBuffer.write(visibleLine[j]);
      lineByVisibleChar.add(i);
    }
    if (i < visibleLines.length - 1) {
      visibleBuffer.write('\n');
      lineByVisibleChar.add(i);
    }
  }

  return _MarkdownVisibleMapping(
    visibleText: visibleBuffer.toString(),
    lineByVisibleChar: lineByVisibleChar,
  );
}

String _lineToVisibleText(String line) {
  var text = line;

  // Leading block markers
  text = text.replaceFirst(RegExp(r'^\s{0,3}#{1,6}\s+'), '');
  text = text.replaceFirst(RegExp(r'^\s*(>\s*)+'), '');
  text = text.replaceFirst(RegExp(r'^\s*[-+*]\s+'), '\u2022 ');
  text = text.replaceFirst(RegExp(r'^\s*\[(?: |x|X)\]\s+'), '\u2022 ');

  // Inline markdown markers
  text = text.replaceAllMapped(
    RegExp(r'!\[([^\]]*)\]\([^)]+\)'),
    (match) => match.group(1) ?? '',
  );
  text = text.replaceAllMapped(
    RegExp(r'\[([^\]]+)\]\([^)]+\)'),
    (match) => match.group(1) ?? '',
  );
  text = text.replaceAllMapped(
    RegExp(r'`([^`]+)`'),
    (match) => match.group(1) ?? '',
  );
  text = text.replaceAll('**', '');
  text = text.replaceAll('__', '');
  text = text.replaceAll('*', '');
  text = text.replaceAll('_', '');
  text = text.replaceAll('~~', '');

  return text;
}

(int, int) _expandMarkdownLineRange({
  required List<String> lines,
  required int startLine,
  required int endLine,
}) {
  var start = startLine;
  var end = endLine;

  // Expand to include full fenced code block when selection intersects it.
  for (final fence in _collectFenceRanges(lines)) {
    final intersects = !(end < fence.$1 || start > fence.$2);
    if (intersects) {
      if (fence.$1 < start) {
        start = fence.$1;
      }
      if (fence.$2 > end) {
        end = fence.$2;
      }
    }
  }

  // Keep contiguous list block structure.
  if (_rangeContainsLineType(lines, start, end, _isListLine)) {
    while (start > 0 && _isListLine(lines[start - 1])) {
      start--;
    }
    while (end + 1 < lines.length && _isListLine(lines[end + 1])) {
      end++;
    }
  }

  // Keep contiguous quote block structure.
  if (_rangeContainsLineType(lines, start, end, _isQuoteLine)) {
    while (start > 0 && _isQuoteLine(lines[start - 1])) {
      start--;
    }
    while (end + 1 < lines.length && _isQuoteLine(lines[end + 1])) {
      end++;
    }
  }

  // Keep contiguous paragraph lines together so markdown context is preserved.
  if (_rangeContainsLineType(lines, start, end, _isParagraphLine)) {
    while (start > 0 && _isParagraphLine(lines[start - 1])) {
      start--;
    }
    while (end + 1 < lines.length && _isParagraphLine(lines[end + 1])) {
      end++;
    }
  }

  return (start, end);
}

bool _rangeContainsLineType(
  List<String> lines,
  int start,
  int end,
  bool Function(String line) matcher,
) {
  for (var i = start; i <= end; i++) {
    if (matcher(lines[i])) {
      return true;
    }
  }
  return false;
}

List<(int, int)> _collectFenceRanges(List<String> lines) {
  final ranges = <(int, int)>[];
  int? currentStart;

  for (var i = 0; i < lines.length; i++) {
    if (!_isFenceLine(lines[i])) {
      continue;
    }
    if (currentStart == null) {
      currentStart = i;
    } else {
      ranges.add((currentStart, i));
      currentStart = null;
    }
  }

  if (currentStart != null) {
    ranges.add((currentStart, lines.length - 1));
  }
  return ranges;
}

bool _isFenceLine(String line) => RegExp(r'^\s*(```|~~~)').hasMatch(line);

bool _isHeadingLine(String line) => RegExp(r'^\s{0,3}#{1,6}\s+').hasMatch(line);

bool _isListLine(String line) {
  final trimmed = line.trimLeft();
  return RegExp(r'^([-+*]|\d+\.)\s+').hasMatch(trimmed);
}

bool _isQuoteLine(String line) => RegExp(r'^\s*>\s?').hasMatch(line);

bool _isThematicBreakLine(String line) =>
    RegExp(r'^\s{0,3}([-*_])(?:\s*\1){2,}\s*$').hasMatch(line);

bool _isParagraphLine(String line) {
  final trimmed = line.trim();
  if (trimmed.isEmpty) {
    return false;
  }
  if (_isFenceLine(line) ||
      _isHeadingLine(line) ||
      _isListLine(line) ||
      _isQuoteLine(line) ||
      _isThematicBreakLine(line)) {
    return false;
  }
  return true;
}

TextStyle _shareTextStyle(
  TextStyle? base, {
  Color? color,
  double? height,
  FontWeight? fontWeight,
  FontStyle? fontStyle,
  TextDecoration? decoration,
  String? fontFamily,
  List<String>? fontFamilyFallback,
}) {
  final resolved = base ?? const TextStyle();
  return resolved.copyWith(
    color: color,
    height: height,
    fontWeight: fontWeight,
    fontStyle: fontStyle,
    decoration: decoration,
    fontFamily: fontFamily ?? kShareImagePrimaryFontFamily,
    fontFamilyFallback: fontFamilyFallback ?? kShareImageFontFallback,
  );
}

_CollapsedTextMapping _collapseWhitespaceWithMapping(String input) {
  final buffer = StringBuffer();
  final originalIndices = <int>[];
  var pendingWhitespace = false;

  for (var i = 0; i < input.length; i++) {
    final char = input[i];
    if (char.trim().isEmpty) {
      pendingWhitespace = true;
      continue;
    }

    if (pendingWhitespace && buffer.isNotEmpty) {
      buffer.write(' ');
      originalIndices.add(i);
    }
    buffer.write(char);
    originalIndices.add(i);
    pendingWhitespace = false;
  }

  return _CollapsedTextMapping(
    collapsedText: buffer.toString(),
    originalIndices: originalIndices,
  );
}

_CompactedTextMapping _compactTextWithMapping(String input) {
  final buffer = StringBuffer();
  final originalIndices = <int>[];

  for (var i = 0; i < input.length; i++) {
    final char = input[i];
    if (char.trim().isEmpty) {
      continue;
    }
    buffer.write(char);
    originalIndices.add(i);
  }

  return _CompactedTextMapping(
    compactText: buffer.toString(),
    originalIndices: originalIndices,
  );
}

class _MarkdownVisibleMapping {
  final String visibleText;
  final List<int> lineByVisibleChar;

  const _MarkdownVisibleMapping({
    required this.visibleText,
    required this.lineByVisibleChar,
  });
}

class _CollapsedTextMapping {
  final String collapsedText;
  final List<int> originalIndices;

  const _CollapsedTextMapping({
    required this.collapsedText,
    required this.originalIndices,
  });
}

class _CompactedTextMapping {
  final String compactText;
  final List<int> originalIndices;

  const _CompactedTextMapping({
    required this.compactText,
    required this.originalIndices,
  });
}

class _VisibleRange {
  final int start;
  final int length;

  const _VisibleRange({required this.start, required this.length});
}

List<ShareConversationItem> truncateConversationItemsForShare({
  required List<ShareConversationItem> items,
  required int maxChars,
  required String truncatedSuffix,
}) {
  final normalizedItems = items
      .map(
        (item) => item.copyWith(
          roleLabel: item.roleLabel.trim(),
          content: item.content.trim(),
        ),
      )
      .where((item) => item.content.isNotEmpty)
      .toList();

  if (normalizedItems.isEmpty) {
    return const <ShareConversationItem>[];
  }

  var remaining = maxChars;
  final result = <ShareConversationItem>[];

  for (final item in normalizedItems) {
    if (remaining <= 0) {
      break;
    }

    if (item.content.length <= remaining) {
      result.add(item);
      remaining -= item.content.length;
      continue;
    }

    final truncated = item.content.substring(0, remaining);
    result.add(item.copyWith(content: '$truncated\n\n$truncatedSuffix'));
    remaining = 0;
    break;
  }

  return result;
}

String formatShareConversationItems(List<ShareConversationItem> items) {
  final blocks = <String>[];
  for (final item in items) {
    final trimmed = item.content.trim();
    if (trimmed.isEmpty) {
      continue;
    }
    blocks.add('[${item.roleLabel}]\n$trimmed');
  }
  return blocks.join('\n\n');
}

String formatChatMessagesForShare({
  required List<PodcastConversationMessage> messages,
  required String userLabel,
  required String assistantLabel,
}) {
  final blocks = <String>[];
  for (final message in messages) {
    final trimmed = message.content.trim();
    if (trimmed.isEmpty) {
      continue;
    }
    final roleLabel = message.isUser ? userLabel : assistantLabel;
    blocks.add('[$roleLabel]\n$trimmed');
  }
  return blocks.join('\n\n');
}

@visibleForTesting
double resolveShareCardWidth({
  required TargetPlatform platform,
  required double screenWidth,
}) {
  switch (platform) {
    case TargetPlatform.android:
    case TargetPlatform.iOS:
      if (screenWidth <= 0) {
        return kShareCardMobileFallbackWidth;
      }
      final candidate = screenWidth - kShareCardMobileHorizontalMargin;
      return candidate
          .clamp(kShareCardMobileMinWidth, kShareCardMobileMaxWidth)
          .toDouble();
    case TargetPlatform.windows:
    case TargetPlatform.macOS:
    case TargetPlatform.linux:
    case TargetPlatform.fuchsia:
      return kShareCardDesktopWidth;
  }
}

@visibleForTesting
double estimateShareImageHeight({
  required ShareImageRenderMode renderMode,
  required int contentLength,
  required int conversationItemCount,
  required double cardWidth,
}) {
  final normalizedLength = contentLength < 0 ? 0 : contentLength;
  final charsPerLine = (cardWidth / 13).clamp(24, 70).toDouble();
  var estimatedLines = (normalizedLength / charsPerLine).ceil();
  if (estimatedLines < 8) {
    estimatedLines = 8;
  }

  var bodyHeight = estimatedLines * kShareImageEstimatedLineHeight;
  switch (renderMode) {
    case ShareImageRenderMode.markdown:
      bodyHeight *= 1.12;
    case ShareImageRenderMode.conversation:
      bodyHeight += conversationItemCount * 36;
    case ShareImageRenderMode.plainText:
      break;
  }

  return (kShareImageEstimatedBaseHeight + bodyHeight)
      .clamp(kShareImageEstimatedBaseHeight, 20000)
      .toDouble();
}

@visibleForTesting
double applyShareImagePixelBudgetGuard({
  required double pixelRatio,
  required double estimatedWidth,
  required double estimatedHeight,
  required double pixelBudget,
}) {
  if (pixelRatio <= kShareImageMinPixelRatio) {
    return kShareImageMinPixelRatio;
  }
  if (estimatedWidth <= 0 || estimatedHeight <= 0 || pixelBudget <= 0) {
    return pixelRatio;
  }

  final estimatedPixels =
      estimatedWidth * estimatedHeight * pixelRatio * pixelRatio;
  if (estimatedPixels <= pixelBudget) {
    return pixelRatio;
  }

  final guardedRatio = math.sqrt(
    pixelBudget / (estimatedWidth * estimatedHeight),
  );
  return guardedRatio.clamp(kShareImageMinPixelRatio, pixelRatio).toDouble();
}

@visibleForTesting
double resolveShareImagePixelRatio({
  required TargetPlatform platform,
  required ShareImageRenderMode renderMode,
  required int contentLength,
  required int conversationItemCount,
  required double cardWidth,
}) {
  final isMobile =
      platform == TargetPlatform.android || platform == TargetPlatform.iOS;
  final normalizedLength = contentLength < 0 ? 0 : contentLength;

  double pixelRatio;
  if (normalizedLength <= 1200) {
    pixelRatio = isMobile ? 1.6 : 1.35;
  } else if (normalizedLength <= 2500) {
    pixelRatio = isMobile ? 1.45 : 1.25;
  } else if (normalizedLength <= 4500) {
    pixelRatio = isMobile ? 1.3 : 1.15;
  } else if (normalizedLength <= 7000) {
    pixelRatio = isMobile ? 1.15 : 1.05;
  } else {
    pixelRatio = 1.0;
  }

  switch (renderMode) {
    case ShareImageRenderMode.markdown:
      pixelRatio += isMobile ? 0.05 : 0.03;
    case ShareImageRenderMode.conversation:
      pixelRatio -= isMobile ? 0.05 : 0.03;
    case ShareImageRenderMode.plainText:
      break;
  }
  pixelRatio = pixelRatio.clamp(kShareImageMinPixelRatio, 1.6).toDouble();

  final estimatedHeight = estimateShareImageHeight(
    renderMode: renderMode,
    contentLength: normalizedLength,
    conversationItemCount: conversationItemCount,
    cardWidth: cardWidth,
  );
  final pixelBudget = isMobile
      ? kShareImageMobilePixelBudget
      : kShareImageDesktopPixelBudget;
  return applyShareImagePixelBudgetGuard(
    pixelRatio: pixelRatio,
    estimatedWidth: cardWidth,
    estimatedHeight: estimatedHeight,
    pixelBudget: pixelBudget,
  );
}

@visibleForTesting
ShareImageExportBehavior resolveImageExportBehavior(TargetPlatform platform) {
  switch (platform) {
    case TargetPlatform.android:
    case TargetPlatform.iOS:
      return ShareImageExportBehavior.share;
    case TargetPlatform.windows:
    case TargetPlatform.macOS:
    case TargetPlatform.linux:
      return ShareImageExportBehavior.save;
    case TargetPlatform.fuchsia:
      return ShareImageExportBehavior.unsupported;
  }
}

class ContentImageShareService {
  static final ScreenshotController _screenshotController =
      ScreenshotController();
  static bool _isShareInProgress = false;

  @visibleForTesting
  static bool get isShareInProgress => _isShareInProgress;

  @visibleForTesting
  static void setShareInProgressForTest(bool value) {
    _isShareInProgress = value;
  }

  static Future<void> shareAsImage(
    BuildContext context,
    ShareImagePayload payload,
  ) async {
    final l10n = AppLocalizations.of(context)!;
    final normalizedText = payload.content.trim();
    final normalizedConversation = payload.conversationItems
        .map(
          (item) => item.copyWith(
            roleLabel: item.roleLabel.trim(),
            content: item.content.trim(),
          ),
        )
        .where((item) => item.content.isNotEmpty)
        .toList();

    if (payload.renderMode == ShareImageRenderMode.conversation) {
      if (normalizedConversation.isEmpty) {
        throw ContentImageShareException(l10n.podcast_share_selection_required);
      }
    } else if (normalizedText.isEmpty) {
      throw ContentImageShareException(l10n.podcast_share_selection_required);
    }

    if (kIsWeb) {
      throw ContentImageShareException(l10n.podcast_share_not_supported);
    }
    final exportBehavior = resolveImageExportBehavior(defaultTargetPlatform);
    if (exportBehavior == ShareImageExportBehavior.unsupported) {
      throw ContentImageShareException(l10n.podcast_share_not_supported);
    }
    if (_isShareInProgress) {
      throw ContentImageShareException(l10n.podcast_share_in_progress);
    }
    _isShareInProgress = true;

    final typeLabel = _resolveTypeLabel(context, payload.contentType);
    final sourceLabel = payload.sourceLabel?.trim().isNotEmpty == true
        ? payload.sourceLabel!.trim()
        : typeLabel;
    final truncatedSuffix = l10n.podcast_share_truncated(payload.maxChars);

    late final String truncatedText;
    late final List<ShareConversationItem> truncatedConversation;

    switch (payload.renderMode) {
      case ShareImageRenderMode.conversation:
        truncatedConversation = truncateConversationItemsForShare(
          items: normalizedConversation,
          maxChars: payload.maxChars,
          truncatedSuffix: truncatedSuffix,
        );
        truncatedText = formatShareConversationItems(truncatedConversation);
      case ShareImageRenderMode.plainText:
      case ShareImageRenderMode.markdown:
        truncatedText = truncateShareContent(
          content: normalizedText,
          maxChars: payload.maxChars,
          truncatedSuffix: truncatedSuffix,
        );
        truncatedConversation = const <ShareConversationItem>[];
    }

    OverlayEntry? preparingOverlayEntry;
    try {
      preparingOverlayEntry = _showPreparingOverlay(
        context,
        message: l10n.podcast_share_preparing_image,
      );
      await Future<void>.delayed(const Duration(milliseconds: 16));
      if (!context.mounted) {
        return;
      }

      final shareOrigin = _resolveShareOrigin(context);
      final fileName = _buildFileName(payload.contentType);
      final cardWidth = resolveShareCardWidth(
        platform: defaultTargetPlatform,
        screenWidth: MediaQuery.sizeOf(context).width,
      );
      final contentLength = _calculateShareContentLength(
        renderMode: payload.renderMode,
        text: truncatedText,
        conversationItems: truncatedConversation,
      );
      final pixelRatio = resolveShareImagePixelRatio(
        platform: defaultTargetPlatform,
        renderMode: payload.renderMode,
        contentLength: contentLength,
        conversationItemCount: truncatedConversation.length,
        cardWidth: cardWidth,
      );

      final bytes = await _screenshotController.captureFromLongWidget(
        _buildShareCard(
          context,
          cardWidth: cardWidth,
          title: payload.episodeTitle.trim().isNotEmpty
              ? payload.episodeTitle.trim()
              : sourceLabel,
          subtitle: sourceLabel,
          body: _buildShareBody(
            context,
            renderMode: payload.renderMode,
            content: truncatedText,
            conversationItems: truncatedConversation,
          ),
        ),
        context: context,
        pixelRatio: pixelRatio,
        delay: const Duration(milliseconds: 60),
      );
      if (!context.mounted) {
        return;
      }

      switch (exportBehavior) {
        case ShareImageExportBehavior.share:
          final tempFile = await _writeTemporaryShareImage(
            bytes: bytes,
            fileName: fileName,
          );
          try {
            await SharePlus.instance.share(
              ShareParams(
                title: payload.episodeTitle,
                subject: payload.episodeTitle,
                text: sourceLabel,
                sharePositionOrigin: shareOrigin,
                files: <XFile>[
                  XFile(tempFile.path, mimeType: 'image/png', name: fileName),
                ],
                fileNameOverrides: <String>[fileName],
              ),
            );
          } finally {
            unawaited(_deleteTemporaryShareImage(tempFile));
          }
          return;
        case ShareImageExportBehavior.save:
          await _saveImage(context, bytes: bytes, fileName: fileName);
          return;
        case ShareImageExportBehavior.unsupported:
          throw ContentImageShareException(l10n.podcast_share_not_supported);
      }
    } on ContentImageShareException {
      rethrow;
    } catch (error, stackTrace) {
      debugPrint('ContentImageShareService.shareAsImage failed: $error');
      debugPrintStack(stackTrace: stackTrace);
      throw ContentImageShareException(l10n.podcast_share_failed);
    } finally {
      preparingOverlayEntry?.remove();
      _isShareInProgress = false;
    }
  }

  static int _calculateShareContentLength({
    required ShareImageRenderMode renderMode,
    required String text,
    required List<ShareConversationItem> conversationItems,
  }) {
    switch (renderMode) {
      case ShareImageRenderMode.conversation:
        var total = 0;
        for (final item in conversationItems) {
          total += item.roleLabel.length;
          total += item.content.length;
        }
        return total;
      case ShareImageRenderMode.plainText:
      case ShareImageRenderMode.markdown:
        return text.length;
    }
  }

  static OverlayEntry? _showPreparingOverlay(
    BuildContext context, {
    required String message,
  }) {
    final overlay = Overlay.maybeOf(context, rootOverlay: true);
    if (overlay == null) {
      return null;
    }

    final entry = OverlayEntry(
      builder: (_) {
        return Stack(
          children: [
            const ModalBarrier(dismissible: false, color: Color(0x4D000000)),
            Center(
              child: Material(
                color: Colors.transparent,
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 20,
                    vertical: 16,
                  ),
                  decoration: BoxDecoration(
                    color: Colors.black87,
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(
                          strokeWidth: 2.2,
                          valueColor: AlwaysStoppedAnimation<Color>(
                            Colors.white,
                          ),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Text(
                        message,
                        style: const TextStyle(color: Colors.white),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ],
        );
      },
    );
    overlay.insert(entry);
    return entry;
  }

  static Future<File> _writeTemporaryShareImage({
    required Uint8List bytes,
    required String fileName,
  }) async {
    final safeName = fileName.replaceAll(RegExp(r'[^A-Za-z0-9._-]'), '_');
    final tempFile = File(
      '${Directory.systemTemp.path}/'
      '${DateTime.now().microsecondsSinceEpoch}_$safeName',
    );
    await tempFile.writeAsBytes(bytes, flush: true);
    return tempFile;
  }

  static Future<void> _deleteTemporaryShareImage(File file) async {
    try {
      if (await file.exists()) {
        await file.delete();
      }
    } catch (error) {
      debugPrint(
        'ContentImageShareService temporary image cleanup failed: $error',
      );
    }
  }

  static Widget _buildShareBody(
    BuildContext context, {
    required ShareImageRenderMode renderMode,
    required String content,
    required List<ShareConversationItem> conversationItems,
  }) {
    final theme = Theme.of(context);

    switch (renderMode) {
      case ShareImageRenderMode.plainText:
        return Text(
          content,
          style: _shareTextStyle(
            theme.textTheme.bodyLarge,
            height: 1.6,
            color: Colors.black,
          ),
        );
      case ShareImageRenderMode.markdown:
        return MarkdownBody(
          data: content,
          styleSheet: MarkdownStyleSheet(
            p: _shareTextStyle(
              theme.textTheme.bodyLarge,
              height: 1.6,
              color: Colors.black,
            ),
            h1: _shareTextStyle(
              theme.textTheme.headlineSmall,
              fontWeight: FontWeight.bold,
              color: Colors.black,
            ),
            h2: _shareTextStyle(
              theme.textTheme.titleLarge,
              fontWeight: FontWeight.bold,
              color: Colors.black,
            ),
            h3: _shareTextStyle(
              theme.textTheme.titleMedium,
              fontWeight: FontWeight.bold,
              color: Colors.black,
            ),
            h4: _shareTextStyle(
              theme.textTheme.titleSmall,
              fontWeight: FontWeight.bold,
              color: Colors.black,
            ),
            h5: _shareTextStyle(
              theme.textTheme.titleSmall,
              fontWeight: FontWeight.bold,
              color: Colors.black,
            ),
            h6: _shareTextStyle(
              theme.textTheme.titleSmall,
              fontWeight: FontWeight.bold,
              color: Colors.black,
            ),
            listBullet: _shareTextStyle(
              theme.textTheme.bodyLarge,
              color: Colors.black,
            ),
            strong: _shareTextStyle(
              theme.textTheme.bodyLarge,
              fontWeight: FontWeight.bold,
              color: Colors.black,
            ),
            em: _shareTextStyle(
              theme.textTheme.bodyLarge,
              color: Colors.black,
              fontStyle: FontStyle.italic,
            ),
            code: _shareTextStyle(
              theme.textTheme.bodyMedium,
              color: Colors.black,
              fontFamily: kShareImageCodeFontFamily,
              fontFamilyFallback: kShareImageCodeFontFallback,
            ),
            blockquote: _shareTextStyle(
              theme.textTheme.bodyMedium,
              color: Colors.black,
              fontStyle: FontStyle.italic,
            ),
            a: _shareTextStyle(
              theme.textTheme.bodyMedium,
              color: Colors.black,
              decoration: TextDecoration.underline,
            ),
          ),
        );
      case ShareImageRenderMode.conversation:
        return Column(
          children: conversationItems
              .map((item) => _buildConversationBubble(context, item))
              .toList(),
        );
    }
  }

  static Widget _buildConversationBubble(
    BuildContext context,
    ShareConversationItem item,
  ) {
    final theme = Theme.of(context);
    final bubbleColor = Colors.white;
    final textColor = Colors.black;
    final borderColor = item.isUser ? Colors.black54 : Colors.black38;

    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Align(
        alignment: item.isUser ? Alignment.centerRight : Alignment.centerLeft,
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 700),
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: BoxDecoration(
              color: bubbleColor,
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: borderColor),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  item.roleLabel,
                  style: _shareTextStyle(
                    theme.textTheme.labelSmall,
                    color: Colors.black,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  item.content,
                  style: _shareTextStyle(
                    theme.textTheme.bodyMedium,
                    color: textColor,
                    height: 1.45,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  static String _resolveTypeLabel(BuildContext context, ShareContentType type) {
    final l10n = AppLocalizations.of(context)!;
    switch (type) {
      case ShareContentType.summary:
        return l10n.podcast_filter_with_summary;
      case ShareContentType.transcript:
        return l10n.podcast_tab_transcript;
      case ShareContentType.chat:
        return l10n.podcast_tab_chat;
    }
  }

  static Rect _resolveShareOrigin(BuildContext context) {
    final renderObject = context.findRenderObject();
    if (renderObject is RenderBox && renderObject.hasSize) {
      return renderObject.localToGlobal(Offset.zero) & renderObject.size;
    }
    final size = MediaQuery.sizeOf(context);
    if (size.width > 0 && size.height > 0) {
      return Offset.zero & size;
    }
    return const Rect.fromLTWH(0, 0, 1, 1);
  }

  static Future<void> _saveImage(
    BuildContext context, {
    required Uint8List bytes,
    required String fileName,
  }) async {
    final l10n = AppLocalizations.of(context)!;
    switch (defaultTargetPlatform) {
      case TargetPlatform.android:
      case TargetPlatform.iOS:
        await _saveImageToGallery(context, bytes: bytes, fileName: fileName);
        break;
      case TargetPlatform.windows:
      case TargetPlatform.macOS:
      case TargetPlatform.linux:
        final location = await file_selector.getSaveLocation(
          suggestedName: fileName,
          confirmButtonText: l10n.save,
          acceptedTypeGroups: const <file_selector.XTypeGroup>[
            file_selector.XTypeGroup(
              label: 'PNG Image',
              extensions: <String>['png'],
            ),
          ],
        );
        if (location == null) {
          return;
        }
        final file = XFile.fromData(
          bytes,
          mimeType: 'image/png',
          name: fileName,
        );
        await file.saveTo(location.path);
        break;
      case TargetPlatform.fuchsia:
        throw ContentImageShareException(l10n.podcast_share_not_supported);
    }

    if (context.mounted) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(l10n.podcast_save_image_success)));
    }
  }

  static Future<void> _saveImageToGallery(
    BuildContext context, {
    required Uint8List bytes,
    required String fileName,
  }) async {
    final l10n = AppLocalizations.of(context)!;
    final granted = await _requestGalleryPermission();
    if (!granted) {
      throw ContentImageShareException(l10n.podcast_save_image_permission);
    }

    final imageName = fileName.endsWith('.png')
        ? fileName.substring(0, fileName.length - 4)
        : fileName;
    final result = await ImageGallerySaverPlus.saveImage(
      bytes,
      name: imageName,
    );
    if (!_isSaveResultSuccess(result)) {
      throw ContentImageShareException(l10n.podcast_save_image_failed);
    }
  }

  static Future<bool> _requestGalleryPermission() async {
    switch (defaultTargetPlatform) {
      case TargetPlatform.android:
        final photosStatus = await Permission.photos.request();
        if (photosStatus.isGranted || photosStatus.isLimited) {
          return true;
        }
        final storageStatus = await Permission.storage.request();
        return storageStatus.isGranted;
      case TargetPlatform.iOS:
        final photosStatus = await Permission.photosAddOnly.request();
        return photosStatus.isGranted || photosStatus.isLimited;
      case TargetPlatform.windows:
      case TargetPlatform.macOS:
      case TargetPlatform.linux:
      case TargetPlatform.fuchsia:
        return true;
    }
  }

  static bool _isSaveResultSuccess(dynamic result) {
    if (result is! Map) {
      return false;
    }
    final success = result['isSuccess'] ?? result['success'];
    if (success is bool) {
      return success;
    }
    if (success is num) {
      return success != 0;
    }
    if (success is String) {
      final normalized = success.toLowerCase();
      return normalized == 'true' || normalized == '1';
    }
    final filePath = result['filePath'] ?? result['path'];
    if (filePath is String) {
      return filePath.trim().isNotEmpty;
    }
    return false;
  }

  static String _buildFileName(ShareContentType type) {
    final now = DateTime.now();
    final yyyy = now.year.toString().padLeft(4, '0');
    final mm = now.month.toString().padLeft(2, '0');
    final dd = now.day.toString().padLeft(2, '0');
    final hh = now.hour.toString().padLeft(2, '0');
    final min = now.minute.toString().padLeft(2, '0');
    final ss = now.second.toString().padLeft(2, '0');
    return 'personal_ai_${type.name}_$yyyy$mm${dd}_$hh$min$ss.png';
  }

  static Widget _buildShareCard(
    BuildContext context, {
    required double cardWidth,
    required String title,
    required String subtitle,
    required Widget body,
  }) {
    final theme = Theme.of(context);
    final isCompactMobileWidth = cardWidth <= kShareCardMobileMaxWidth;
    final outerPadding = isCompactMobileWidth ? 20.0 : 28.0;
    final contentPadding = isCompactMobileWidth ? 14.0 : 16.0;

    return Material(
      color: Colors.white,
      child: Container(
        width: cardWidth,
        padding: EdgeInsets.all(outerPadding),
        decoration: BoxDecoration(
          color: Colors.white,
          border: Border.all(color: Colors.black38, width: 1.2),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            DefaultTextStyle.merge(
              style: _shareTextStyle(
                theme.textTheme.bodyMedium,
                color: Colors.black,
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: _shareTextStyle(
                      theme.textTheme.titleLarge,
                      fontWeight: FontWeight.w700,
                      color: Colors.black,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 10,
                      vertical: 5,
                    ),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: Colors.black38, width: 1),
                    ),
                    child: Text(
                      subtitle,
                      style: _shareTextStyle(
                        theme.textTheme.labelMedium,
                        color: Colors.black,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Container(
                    width: double.infinity,
                    padding: EdgeInsets.all(contentPadding),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: Colors.black38, width: 1.1),
                    ),
                    child: body,
                  ),
                  const SizedBox(height: 14),
                  Text(
                    'Generated by Personal AI Assistant',
                    style: _shareTextStyle(
                      theme.textTheme.labelSmall,
                      color: Colors.black,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    softWrap: false,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
