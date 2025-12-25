import 'dart:io';
import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:desktop_drop/desktop_drop.dart';

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
  bool _isImporting = false;
  bool _isDragging = false;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    _textController.dispose();
    super.dispose();
  }

  // Regex to find http/https links
  final RegExp _urlRegex = RegExp(
    r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)',
    caseSensitive: false,
    multiLine: true,
  );

  void _analyzeText() {
    final text = _textController.text;
    if (text.isEmpty) return;

    setState(() {
      _previewUrls = _extractUrls(text);
    });
  }

  List<String> _extractUrls(String content) {
    final urls = _urlRegex.allMatches(content).map((m) => m.group(0)!).toSet().toList();
    return urls;
  }

  Future<void> _processFile(String path) async {
    try {
      debugPrint('== Processing file: $path ==');
      final file = File(path);
      final content = await file.readAsString();
      final urls = _extractUrls(content);
      
      if (mounted) {
        setState(() {
          _previewUrls.addAll(urls);
          _previewUrls = _previewUrls.toSet().toList();
          
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Extracted ${urls.length} URLs from file')),
          );
        });
      }
    } catch (e) {
      debugPrint('Error reading file: $e');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to read file: $e'), backgroundColor: Colors.red),
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
    if (_previewUrls.isEmpty) return;

    setState(() {
      _isImporting = true;
    });

    try {
      await widget.onImport(_previewUrls);
      if (mounted) {
        Navigator.of(context).pop();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Successfully imported ${_previewUrls.length} subscriptions')),
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

  @override
  Widget build(BuildContext context) {
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
        child: Center(
          child: Container(
            width: 600,
            height: 700,
            decoration: BoxDecoration(
              color: _isDragging 
                  ? Theme.of(context).primaryColor.withOpacity(0.15)
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
            padding: const EdgeInsets.all(24),
            child: Material(
              color: Colors.transparent,
              child: Column(
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
                        child: const Text('Drop files here!', style: TextStyle(fontWeight: FontWeight.bold)),
                      ),
                    ),
                  const SizedBox(height: 16),
                  TabBar(
                    controller: _tabController,
                    tabs: const [
                      Tab(text: 'Paste Text'),
                      Tab(text: 'Drop/Upload File'), 
                    ],
                  ),
                  const SizedBox(height: 16),
                  Expanded(
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
                          child: Column(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              const Icon(Icons.upload_file, size: 64, color: Colors.grey),
                              const SizedBox(height: 16),
                              const Text('Drag & Drop any file here', 
                                style: TextStyle(fontSize: 18, fontWeight: FontWeight.w500)),
                              const SizedBox(height: 16),
                              OutlinedButton.icon(
                                onPressed: _pickFile,
                                icon: const Icon(Icons.folder_open),
                                label: const Text('Select File'),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                  const Divider(height: 48),
                  Text(
                    'Preview (${_previewUrls.length} links found)',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  Expanded(
                    child: Container(
                      decoration: BoxDecoration(
                        border: Border.all(color: Theme.of(context).colorScheme.outlineVariant),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: ListView.builder(
                        itemCount: _previewUrls.length,
                        itemBuilder: (context, index) {
                          return ListTile(
                            dense: true,
                            title: Text(_previewUrls[index]),
                            trailing: IconButton(
                              icon: const Icon(Icons.remove_circle, color: Colors.red, size: 18),
                              onPressed: () => setState(() => _previewUrls.removeAt(index)),
                            ),
                          );
                        },
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.end,
                    children: [
                      TextButton(
                        onPressed: () => Navigator.of(context).pop(),
                        child: const Text('Cancel'),
                      ),
                      const SizedBox(width: 8),
                      FilledButton(
                        onPressed: _previewUrls.isNotEmpty && !_isImporting ? _import : null,
                        child: _isImporting
                            ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                            : const Text('Import All'),
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
