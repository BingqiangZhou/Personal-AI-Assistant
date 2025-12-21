import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';
import 'package:file_selector/file_selector.dart';

import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../providers/knowledge_providers.dart';
import '../../data/models/knowledge_model.dart';

class KnowledgeBasePage extends ConsumerStatefulWidget {
  const KnowledgeBasePage({super.key});

  @override
  ConsumerState<KnowledgeBasePage> createState() => _KnowledgeBasePageState();
}

class _KnowledgeBasePageState extends ConsumerState<KnowledgeBasePage> {
  final TextEditingController _searchController = TextEditingController();
  KnowledgeBaseModel? _selectedBase;

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ResponsiveContainer(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          _buildHeader(context),
          const SizedBox(height: 24),

          // Search & Filter
          _buildSearchAndFilter(context),
          const SizedBox(height: 24),

          // Content
          Expanded(
            child: _searchController.text.isNotEmpty
                ? _buildSearchResults(context, _searchController.text)
                : _selectedBase == null
                    ? _buildBasesList(context)
                    : _buildDocumentsList(context, _selectedBase!),
          ),
        ],
      ),
    );
  }

  Widget _buildHeader(BuildContext context) {
    return SizedBox(
      height: 56,
      child: Row(
        children: [
          if (_selectedBase != null)
            IconButton(
              icon: const Icon(Icons.arrow_back),
              onPressed: () => setState(() => _selectedBase = null),
            ),
          Expanded(
            child: Text(
              _selectedBase?.name ?? 'Knowledge Base',
              style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
            ),
          ),
          const SizedBox(width: 16),
          Row(
            children: [
              FilledButton.tonal(
                onPressed: () => _showImportDialog(context),
                child: const Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.upload, size: 16),
                    SizedBox(width: 4),
                    Text('Import'),
                  ],
                ),
              ),
              const SizedBox(width: 12),
              FilledButton.icon(
                onPressed: () => _showCreateDialog(context),
                icon: const Icon(Icons.add),
                label: const Text('Create'),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildSearchAndFilter(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        children: [
          TextFormField(
            controller: _searchController,
            onFieldSubmitted: (value) => setState(() {}),
            decoration: InputDecoration(
              hintText: 'Search across all knowledge bases...',
              prefixIcon: const Icon(Icons.search),
              suffixIcon: IconButton(
                onPressed: () {
                  _searchController.clear();
                  setState(() {});
                },
                icon: const Icon(Icons.clear),
              ),
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
              contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSearchResults(BuildContext context, String query) {
    final searchAsync = ref.watch(searchDocumentsProvider(query));

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 8.0),
          child: Text('Search Results for "$query"', style: Theme.of(context).textTheme.titleMedium),
        ),
        Expanded(
          child: searchAsync.when(
            data: (docs) {
              if (docs.isEmpty) return const Center(child: Text('No results found.'));
              return ListView.builder(
                itemCount: docs.length,
                itemBuilder: (context, index) {
                  final doc = docs[index];
                  return ListTile(
                    leading: Icon(_getDocIcon(doc.contentType)),
                    title: Text(doc.title),
                    subtitle: Text('In knowledge base ID: ${doc.knowledgeBaseId}'),
                    onTap: () => _openDocument(doc),
                  );
                },
              );
            },
            loading: () => const Center(child: CircularProgressIndicator()),
            error: (err, stack) => Center(child: Text('Error: $err')),
          ),
        ),
      ],
    );
  }

  Widget _buildBasesList(BuildContext context) {
    final basesAsync = ref.watch(knowledgeBasesProvider);

    return basesAsync.when(
      data: (bases) {
        if (bases.isEmpty) {
          return const Center(child: Text('No knowledge bases found. Create one to get started!'));
        }

        final isMobile = MediaQuery.of(context).size.width < 600;

        if (isMobile) {
          return ListView.builder(
            itemCount: bases.length,
            itemBuilder: (context, index) => _buildBaseTile(context, bases[index]),
          );
        }

        return GridView.builder(
          gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: 3,
            crossAxisSpacing: 16,
            mainAxisSpacing: 16,
            childAspectRatio: 1.5,
          ),
          itemCount: bases.length,
          itemBuilder: (context, index) => _buildBaseCard(context, bases[index]),
        );
      },
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (err, stack) => Center(child: Text('Error: $err')),
    );
  }

  Widget _buildBaseTile(BuildContext context, KnowledgeBaseModel base) {
    return Card(
      margin: const EdgeInsets.symmetric(vertical: 4, horizontal: 8),
      child: ListTile(
        leading: const CircleAvatar(child: Icon(Icons.folder)),
        title: Text(base.name),
        subtitle: Text('${base.documentCount} documents'),
        trailing: const Icon(Icons.chevron_right),
        onTap: () => setState(() => _selectedBase = base),
      ),
    );
  }

  Widget _buildBaseCard(BuildContext context, KnowledgeBaseModel base) {
    return Card(
      child: InkWell(
        onTap: () => setState(() => _selectedBase = base),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Icon(Icons.folder, size: 32),
              const SizedBox(height: 12),
              Text(
                base.name,
                style: Theme.of(context).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.bold),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
              const SizedBox(height: 4),
              Text(
                base.description ?? 'No description',
                style: Theme.of(context).textTheme.bodySmall,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
              const Spacer(),
              Text('${base.documentCount} documents', style: Theme.of(context).textTheme.labelSmall),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDocumentsList(BuildContext context, KnowledgeBaseModel base) {
    final docsAsync = ref.watch(documentsProvider(base.id));

    return docsAsync.when(
      data: (docs) {
        if (docs.isEmpty) {
          return const Center(child: Text('No documents in this knowledge base.'));
        }

        return ListView.builder(
          itemCount: docs.length,
          itemBuilder: (context, index) {
            final doc = docs[index];
            return ListTile(
              leading: Icon(_getDocIcon(doc.contentType)),
              title: Text(doc.title),
              subtitle: Text('Added ${DateFormat.yMMMd().format(doc.createdAt)}'),
              onTap: () => _openDocument(doc),
            );
          },
        );
      },
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (err, stack) => Center(child: Text('Error: $err')),
    );
  }

  IconData _getDocIcon(String contentType) {
    switch (contentType.toLowerCase()) {
      case 'pdf': return Icons.picture_as_pdf;
      case 'markdown':
      case 'md': return Icons.code;
      case 'txt': return Icons.article;
      default: return Icons.description;
    }
  }

  void _openDocument(DocumentModel doc) {
    // TODO: Implement document viewer page
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('Opening: ${doc.title}')),
    );
  }

  void _showImportDialog(BuildContext context) {
    if (_selectedBase == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please select a knowledge base first')),
      );
      return;
    }

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Import Knowledge'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.file_upload),
              title: const Text('Upload File'),
              onTap: () {
                Navigator.pop(context);
                _importFile();
              },
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
        ],
      ),
    );
  }

  Future<void> _importFile() async {
    const XTypeGroup typeGroup = XTypeGroup(
      label: 'documents',
      extensions: <String>['pdf', 'docx', 'txt', 'md'],
    );
    final XFile? file = await openFile(acceptedTypeGroups: <XTypeGroup>[typeGroup]);
    
    if (file != null && _selectedBase != null) {
      final bytes = await file.readAsBytes();
      await ref.read(documentsProvider(_selectedBase!.id).notifier).uploadDocument(
        bytes,
        file.name,
      );
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Uploaded ${file.name}')),
        );
      }
    }
  }

  void _showCreateDialog(BuildContext context) {
    final nameController = TextEditingController();
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Create Knowledge Base'),
        content: TextField(
          controller: nameController,
          decoration: const InputDecoration(labelText: 'Name'),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
          TextButton(
            onPressed: () async {
              if (nameController.text.isNotEmpty) {
                await ref.read(knowledgeBasesProvider.notifier).addKnowledgeBase(
                  name: nameController.text,
                );
                if (context.mounted) {
                  Navigator.pop(context);
                }
              }
            },
            child: const Text('Create'),
          ),
        ],
      ),
    );
  }
}