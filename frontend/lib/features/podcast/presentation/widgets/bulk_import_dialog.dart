import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:file_picker/file_picker.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:xml/xml.dart';
import 'package:dio/dio.dart';

import '../../../../core/localization/app_localizations.dart';

/// Model to represent URL validation status
class UrlValidationItem {
  final String url;
  final String? title;  // Optional title from OPML file
  bool isValid;
  bool isChecking;
  String? errorMessage;

  UrlValidationItem({
    required this.url,
    this.title,
    this.isValid = false,
    this.isChecking = true,
    this.errorMessage,
  });
}

/// Model to represent URL with optional title from OPML
class UrlWithTitle {
  final String url;
  final String? title;

  UrlWithTitle({
    required this.url,
    this.title,
  });
}

class BulkImportDialog extends StatefulWidget {
  final Future<void> Function(List<String> urls) onImport;

  const BulkImportDialog({
    super.key,
    required this.onImport,
  });

  @override
  State<BulkImportDialog> createState() => _BulkImportDialogState();
}

class _BulkImportDialogState extends State<BulkImportDialog> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final TextEditingController _textController = TextEditingController();
  List<String> _previewUrls = [];
  List<UrlValidationItem> _validationItems = [];
  bool _isImporting = false;
  bool _isDragging = false;
  final Dio _dio = Dio();

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    _textController.dispose();
    _dio.close();
    super.dispose();
  }

  // Regex to find http/https links
  final RegExp _urlRegex = RegExp(
    r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)',
    caseSensitive: false,
    multiLine: true,
  );

  void _analyzeText() async {
    final text = _textController.text;
    if (text.isEmpty) return;

    final urls = _extractUrls(text);

    if (urls.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('No URLs found in text')),
        );
      }
      return;
    }

    // Validate URLs in background (append to existing list)
    await _validateUrls(urls, append: true);

    if (mounted) {
      final validCount = _validationItems.where((item) => item.isValid).length;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Found ${urls.length} links, $validCount valid RSS feeds'),
          duration: const Duration(seconds: 3),
        ),
      );
    }
  }

  List<String> _extractUrls(String content) {
    final urls = _urlRegex.allMatches(content).map((m) => m.group(0)!).toSet().toList();
    return urls;
  }

  /// Extract RSS feed URLs from OPML file content
  /// OPML (Outline Processor Markup Language) is an XML format for storing subscription lists
  /// Returns a list of UrlWithTitle objects containing both URL and title
  List<UrlWithTitle> _extractOpmlUrls(String content) {
    final urlsWithTitles = <UrlWithTitle>[];

    try {
      final document = XmlDocument.parse(content);

      // Find all outline elements with xmlUrl attribute (RSS feeds)
      final outlines = document.findAllElements('outline');

      for (final outline in outlines) {
        String? feedUrl;
        String? feedTitle;

        // Try xmlUrl attribute first (standard OPML for RSS feeds)
        feedUrl = outline.getAttribute('xmlUrl');
        if (feedUrl == null || !feedUrl.startsWith('http')) {
          // Try url attribute as fallback (some OPML variants use this)
          feedUrl = outline.getAttribute('url');
          if (feedUrl == null || !feedUrl.startsWith('http')) {
            continue;
          }
        }

        // Extract title from title attribute (not text)
        feedTitle = outline.getAttribute('title') ??
                    outline.getAttribute('xmlUrl');

        urlsWithTitles.add(UrlWithTitle(
          url: feedUrl,
          title: feedTitle,
        ));
      }

      debugPrint('== OPML parsing: found ${urlsWithTitles.length} RSS feeds with titles ==');
    } catch (e) {
      debugPrint('Error parsing OPML: $e');
      // If OPML parsing fails, fall back to regex extraction (without titles)
      final urls = _extractUrls(content);
      return urls.map((url) => UrlWithTitle(url: url, title: null)).toList();
    }

    // Remove duplicates based on URL
    final uniqueMap = <String, UrlWithTitle>{};
    for (final item in urlsWithTitles) {
      uniqueMap[item.url] = item;
    }
    return uniqueMap.values.toList();
  }

  /// Validate if a URL is a valid RSS feed by checking the content
  Future<bool> _validateRssUrl(String url) async {
    try {
      // Set timeout to 5 seconds
      final response = await _dio.get(
        url,
        options: Options(
          responseType: ResponseType.plain,
          sendTimeout: const Duration(seconds: 5),
          receiveTimeout: const Duration(seconds: 5),
          headers: {
            'User-Agent': 'Mozilla/5.0 (Compatible; RSS Reader)',
          },
        ),
      );

      final content = response.data.toString().toLowerCase();

      // Check for RSS/Atom feed indicators
      final hasRssTag = content.contains('<rss') || content.contains('<rdf:rdf');
      final hasAtomTag = content.contains('<feed') || content.contains('<entry>');
      final hasXmlDecl = content.contains('<?xml');

      return hasRssTag || hasAtomTag || (hasXmlDecl && (hasRssTag || hasAtomTag));
    } catch (e) {
      debugPrint('Error validating RSS URL $url: $e');
      return false;
    }
  }

  /// Validate all URLs and update the validation items
  /// [append] if true, append to existing list; if false, replace the list
  Future<void> _validateUrls(List<String> urls, {bool append = false}) async {
    // Remove duplicates from new URLs
    final existingUrls = _validationItems.map((item) => item.url).toSet();
    final newUrls = urls.where((url) => !existingUrls.contains(url)).toList();

    if (newUrls.isEmpty) {
      if (mounted && append) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('All URLs already exist in the list'),
            duration: Duration(seconds: 2),
          ),
        );
      }
      return;
    }

    final items = newUrls.map((url) => UrlValidationItem(url: url)).toList();

    setState(() {
      if (append) {
        _validationItems.addAll(items);
        _previewUrls.addAll(newUrls);
      } else {
        _validationItems = items;
        _previewUrls = newUrls;
      }
    });

    // Validate each URL in parallel with concurrency limit
    final futures = <Future<void>>[];
    const concurrencyLimit = 5;

    for (var i = 0; i < items.length; i++) {
      if (futures.length >= concurrencyLimit) {
        await Future.wait(futures);
        futures.clear();
      }

      final item = items[i];
      futures.add(_validateSingleUrl(item));
    }

    if (futures.isNotEmpty) {
      await Future.wait(futures);
    }

    setState(() {});
  }

  /// Validate all URLs with titles and update the validation items
  /// [append] if true, append to existing list; if false, replace the list
  Future<void> _validateUrlsWithTitles(List<UrlWithTitle> urlsWithTitles, {bool append = false}) async {
    // Remove duplicates from new URLs
    final existingUrls = _validationItems.map((item) => item.url).toSet();
    final newUrlsWithTitles = urlsWithTitles.where((item) => !existingUrls.contains(item.url)).toList();

    if (newUrlsWithTitles.isEmpty) {
      if (mounted && append) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('All URLs already exist in the list'),
            duration: Duration(seconds: 2),
          ),
        );
      }
      return;
    }

    final items = newUrlsWithTitles.map((item) =>
      UrlValidationItem(url: item.url, title: item.title)
    ).toList();
    final newUrls = newUrlsWithTitles.map((item) => item.url).toList();

    setState(() {
      if (append) {
        _validationItems.addAll(items);
        _previewUrls.addAll(newUrls);
      } else {
        _validationItems = items;
        _previewUrls = newUrls;
      }
    });

    // Validate each URL in parallel with concurrency limit
    final futures = <Future<void>>[];
    const concurrencyLimit = 5;

    for (var i = 0; i < items.length; i++) {
      if (futures.length >= concurrencyLimit) {
        await Future.wait(futures);
        futures.clear();
      }

      final item = items[i];
      futures.add(_validateSingleUrl(item));
    }

    if (futures.isNotEmpty) {
      await Future.wait(futures);
    }

    setState(() {});
  }

  /// Validate a single URL and update its status
  Future<void> _validateSingleUrl(UrlValidationItem item) async {
    final isValid = await _validateRssUrl(item.url);

    if (mounted) {
      setState(() {
        item.isValid = isValid;
        item.isChecking = false;
        item.errorMessage = isValid ? null : 'Not a valid RSS feed';
      });
    }
  }

  Future<void> _processFile(String path) async {
    try {
      debugPrint('== Processing file: $path ==');
      final file = File(path);
      final content = await file.readAsString();

      // Check if this is an OPML file by extension
      final isOpmlFile = path.toLowerCase().endsWith('.opml');

      if (isOpmlFile) {
        debugPrint('== Detected OPML file, using OPML parser ==');
        final urlsWithTitles = _extractOpmlUrls(content);

        if (urlsWithTitles.isEmpty) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('No URLs found in file')),
            );
          }
          return;
        }

        // Validate URLs with titles (append to existing list)
        await _validateUrlsWithTitles(urlsWithTitles, append: true);

        if (mounted) {
          final validCount = _validationItems.where((item) => item.isValid).length;
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Found ${urlsWithTitles.length} links, $validCount valid RSS feeds'),
              duration: const Duration(seconds: 3),
            ),
          );
        }
      } else {
        debugPrint('== Detected text file, using regex parser ==');
        final urls = _extractUrls(content);

        if (urls.isEmpty) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('No URLs found in file')),
            );
          }
          return;
        }

        // Validate URLs in background (append to existing list)
        await _validateUrls(urls, append: true);

        if (mounted) {
          final validCount = _validationItems.where((item) => item.isValid).length;
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Found ${urls.length} links, $validCount valid RSS feeds'),
              duration: const Duration(seconds: 3),
            ),
          );
        }
      }
    } catch (e) {
      debugPrint('Error reading file: $e');
      if (mounted) {
        final l10n = AppLocalizations.of(context)!;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(l10n.podcast_bulk_import_file_error(e.toString())), backgroundColor: Colors.red),
        );
      }
    }
  }

  Future<void> _pickFile() async {
    try {
      FilePickerResult? result = await FilePicker.platform.pickFiles(
        type: FileType.any,
        allowMultiple: false,
      );

      if (result != null && result.files.single.path != null) {
        await _processFile(result.files.single.path!);
      }
    } catch (e) {
      debugPrint('Error picking file: $e');
    }
  }

  Future<void> _import() async {
    if (_validationItems.isEmpty) return;

    // Only import valid RSS URLs
    final validUrls = _validationItems
        .where((item) => item.isValid)
        .map((item) => item.url)
        .toList();

    if (validUrls.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('No valid RSS feeds to import. Please remove invalid URLs or wait for validation to complete.'),
            backgroundColor: Colors.orange,
            duration: Duration(seconds: 3),
          ),
        );
      }
      return;
    }

    setState(() {
      _isImporting = true;
    });

    try {
      await widget.onImport(validUrls);
      if (mounted) {
        Navigator.of(context).pop();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Successfully imported ${validUrls.length} RSS feeds')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Import failed: $e'), backgroundColor: Colors.red),
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _isImporting = false;
        });
      }
    }
  }

  bool _hasValidUrls() {
    return _validationItems.any((item) => item.isValid);
  }

  String _getImportButtonText() {
    final validCount = _validationItems.where((item) => item.isValid).length;
    if (validCount > 0) {
      return 'Import $validCount Valid RSS${validCount > 1 ? ' Feeds' : ' Feed'}';
    }
    return 'Import All';
  }

  Widget _buildPreviewHeader() {
    final totalCount = _validationItems.length;
    final validCount = _validationItems.where((item) => item.isValid).length;
    final checkingCount = _validationItems.where((item) => item.isChecking).length;
    final invalidCount = totalCount - validCount - checkingCount;

    return Row(
      children: [
        Text(
          'Preview ($totalCount links)',
          style: Theme.of(context).textTheme.titleMedium,
        ),
        if (totalCount > 0) ...[
          const SizedBox(width: 12),
          _buildStatusChip('Valid: $validCount', Colors.green, Icons.check_circle),
          if (invalidCount > 0)
            _buildStatusChip('Invalid: $invalidCount', Colors.red, Icons.cancel),
          if (checkingCount > 0)
            _buildStatusChip('Checking: $checkingCount', Colors.orange, Icons.hourglass_empty),
        ],
      ],
    );
  }

  Widget _buildStatusChip(String label, Color color, IconData icon) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color, width: 1),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 14, color: color),
          const SizedBox(width: 4),
          Text(
            label,
            style: TextStyle(
              fontSize: 12,
              color: color,
              fontWeight: FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyPreview() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.link_off,
            size: 48,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          const SizedBox(height: 12),
          Text(
            'No URLs added yet',
            style: TextStyle(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Paste text or upload a file to extract RSS links',
            style: TextStyle(
              fontSize: 12,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildUrlListItem(UrlValidationItem item, int index) {
    Color statusColor;
    IconData statusIcon;
    String statusText;

    if (item.isChecking) {
      statusColor = Colors.orange;
      statusIcon = Icons.hourglass_empty;
      statusText = 'Checking...';
    } else if (item.isValid) {
      statusColor = Colors.green;
      statusIcon = Icons.check_circle;
      statusText = 'Valid RSS';
    } else {
      statusColor = Colors.red;
      statusIcon = Icons.cancel;
      statusText = 'Invalid';
    }

    return ListTile(
      dense: true,
      minVerticalPadding: 0,
      contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      leading: Icon(statusIcon, color: statusColor, size: 20),
      title: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                // Show title if available (from OPML)
                if (item.title != null && item.title!.isNotEmpty)
                  Text(
                    item.title!,
                    style: const TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                // URL
                Text(
                  item.url,
                  style: TextStyle(
                    fontSize: item.title != null ? 10 : 11,
                    color: item.title != null
                        ? Theme.of(context).colorScheme.onSurfaceVariant
                        : null,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          // Copy button
          IconButton(
            icon: const Icon(Icons.copy, size: 14),
            onPressed: () => _copyUrlToClipboard(item.url),
            tooltip: 'Copy URL',
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
            splashRadius: 16,
          ),
        ],
      ),
      subtitle: Text(
        statusText,
        style: TextStyle(
          fontSize: 10,
          color: statusColor,
          fontWeight: FontWeight.w500,
        ),
      ),
      trailing: IconButton(
        icon: const Icon(Icons.remove_circle, color: Colors.red, size: 18),
        onPressed: () => setState(() {
          _validationItems.removeAt(index);
          _previewUrls.removeAt(index);
        }),
        tooltip: 'Remove',
        padding: EdgeInsets.zero,
        constraints: const BoxConstraints(),
        splashRadius: 16,
      ),
    );
  }

  Future<void> _copyUrlToClipboard(String url) async {
    await Clipboard.setData(ClipboardData(text: url));
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('URL copied to clipboard'),
          duration: const Duration(seconds: 2),
          behavior: SnackBarBehavior.floating,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    // We put DropTarget at the very top of the Dialog's child tree
    return DropTarget(
      onDragEntered: (detail) {
        debugPrint('WINDWOS_DRAG: Entered');
        setState(() => _isDragging = true);
      },
      onDragExited: (detail) {
        debugPrint('WINDWOS_DRAG: Exited');
        setState(() => _isDragging = false);
      },
      onDragDone: (detail) async {
        debugPrint('WINDWOS_DRAG: Done - ${detail.files.length} files');
        for (final file in detail.files) {
          await _processFile(file.path);
        }
        setState(() => _isDragging = false);
      },
      child: Dialog(
        backgroundColor: Colors.transparent,
        elevation: 0,
        insetPadding: const EdgeInsets.symmetric(
          horizontal: 20,
          vertical: 24,
        ),
        child: Center(
          child: Container(
            width: 600,
            constraints: const BoxConstraints(maxHeight: 900),
            decoration: BoxDecoration(
              color: _isDragging
                  ? Theme.of(context).primaryColor.withValues(alpha: 0.15)
                  : Theme.of(context).dialogBackgroundColor,
              border: Border.all(
                color: _isDragging ? Theme.of(context).primaryColor : Colors.transparent,
                width: 2,
              ),
              borderRadius: BorderRadius.circular(28),
              boxShadow: const [
                BoxShadow(color: Colors.black26, blurRadius: 16, offset: Offset(0, 8)),
              ],
            ),
            padding: const EdgeInsets.all(16),
            child: Material(
              color: Colors.transparent,
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.playlist_add, size: 28),
                      const SizedBox(width: 12),
                      Text(
                        'Bulk Import',
                        style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const Spacer(),
                      IconButton(
                        onPressed: () => Navigator.of(context).pop(),
                        icon: const Icon(Icons.close),
                      ),
                    ],
                  ),
                  if (_isDragging)
                    Padding(
                      padding: const EdgeInsets.only(top: 16),
                      child: Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: Theme.of(context).colorScheme.primaryContainer,
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Text(l10n.drop_files_here, style: const TextStyle(fontWeight: FontWeight.bold)),
                      ),
                    ),
                  const SizedBox(height: 12),
                  TabBar(
                    controller: _tabController,
                    tabs: const [
                      Tab(text: 'Paste Text'),
                      Tab(text: 'Drop/Upload File'),
                    ],
                  ),
                  const SizedBox(height: 12),
                  SizedBox(
                    height: 200,
                    child: TabBarView(
                      controller: _tabController,
                      children: [
                        Column(
                          children: [
                            Expanded(
                              child: TextField(
                                controller: _textController,
                                maxLines: null,
                                expands: true,
                                decoration: const InputDecoration(
                                  border: OutlineInputBorder(),
                                  hintText: 'Paste content here... URLs will be extracted.',
                                  alignLabelWithHint: true,
                                ),
                              ),
                            ),
                            const SizedBox(height: 12),
                            Align(
                              alignment: Alignment.centerRight,
                              child: FilledButton.icon(
                                onPressed: _analyzeText,
                                icon: const Icon(Icons.auto_awesome),
                                label: const Text('Extract URLs'),
                              ),
                            ),
                          ],
                        ),
                        Container(
                          decoration: BoxDecoration(
                            border: Border.all(color: Theme.of(context).dividerColor),
                            borderRadius: BorderRadius.circular(16),
                            color: Theme.of(context).colorScheme.surfaceContainerLow,
                          ),
                          child: Center(
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                Row(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  children: [
                                    const Icon(Icons.upload_file, size: 32, color: Colors.grey),
                                    const SizedBox(width: 12),
                                    const Text(
                                      'Drag & Drop files here',
                                      style: TextStyle(fontSize: 16, fontWeight: FontWeight.w500),
                                    ),
                                  ],
                                ),
                                const SizedBox(height: 16),
                                OutlinedButton.icon(
                                  onPressed: _pickFile,
                                  icon: const Icon(Icons.folder_open, size: 18),
                                  label: const Text('Select File'),
                                ),
                              ],
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const Divider(height: 32),
                  _buildPreviewHeader(),
                  const SizedBox(height: 8),
                  Expanded(
                    child: Container(
                      decoration: BoxDecoration(
                        border: Border.all(color: Theme.of(context).colorScheme.outlineVariant),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: _validationItems.isEmpty
                          ? _buildEmptyPreview()
                          : ListView.builder(
                              itemCount: _validationItems.length,
                              itemBuilder: (context, index) {
                                return _buildUrlListItem(_validationItems[index], index);
                              },
                            ),
                    ),
                  ),
                  const SizedBox(height: 12),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.end,
                    children: [
                      TextButton(
                        onPressed: () => Navigator.of(context).pop(),
                        child: Text(l10n.cancel),
                      ),
                      const SizedBox(width: 8),
                      FilledButton(
                        onPressed: _hasValidUrls() && !_isImporting ? _import : null,
                        child: _isImporting
                            ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                            : Text(_getImportButtonText()),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
