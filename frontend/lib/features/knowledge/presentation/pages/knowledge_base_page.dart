import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_selector/file_selector.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../../../../core/utils/time_formatter.dart';
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
          const SizedBox(height: 8),

          // Search & Filter
          _buildSearchAndFilter(context),
          const SizedBox(height: 8),

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
    final l10n = AppLocalizations.of(context)!;
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
              _selectedBase?.name ?? l10n.knowledge_base,
              style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
            ),
          ),
          const SizedBox(width: 16),
          IconButton(
            onPressed: () => _showImportDialog(context),
            icon: const Icon(Icons.upload),
            tooltip: l10n.knowledge_upload_document,
          ),
          IconButton(
            onPressed: () => _showCreateDialog(context),
            icon: const Icon(Icons.add),
            tooltip: l10n.create,
          ),
        ],
      ),
    );
  }

  Widget _buildSearchAndFilter(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
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
              hintText: l10n.search,
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
    final l10n = AppLocalizations.of(context)!;
    final searchAsync = ref.watch(searchDocumentsProvider(query));

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 8.0),
          child: Text('${l10n.search} Results for "$query"', style: Theme.of(context).textTheme.titleMedium),
        ),
        Expanded(
          child: searchAsync.when(
            data: (docs) {
              if (docs.isEmpty) return Center(child: Text(l10n.no_results));
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
            error: (err, stack) => Center(child: Text('${l10n.error}: $err')),
          ),
        ),
      ],
    );
  }

  Widget _buildBasesList(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final basesAsync = ref.watch(knowledgeBasesProvider);

    return basesAsync.when(
      data: (bases) {
        if (bases.isEmpty) {
          return Center(child: Text(l10n.knowledge_no_bases));
        }

        final isMobile = MediaQuery.of(context).size.width < 600;

        if (isMobile) {
          return ListView.builder(
            padding: const EdgeInsets.symmetric(vertical: 4),
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
      error: (err, stack) => Center(child: Text('${l10n.error}: $err')),
    );
  }

  Widget _buildBaseTile(BuildContext context, KnowledgeBaseModel base) {
    final l10n = AppLocalizations.of(context)!;
    return Card(
      margin: const EdgeInsets.symmetric(vertical: 4, horizontal: 8),
      child: ListTile(
        leading: const CircleAvatar(child: Icon(Icons.folder)),
        title: Text(base.name),
        subtitle: Text('${base.documentCount} ${l10n.knowledge_documents}'),
        trailing: const Icon(Icons.chevron_right),
        onTap: () => setState(() => _selectedBase = base),
      ),
    );
  }

  Widget _buildBaseCard(BuildContext context, KnowledgeBaseModel base) {
    final l10n = AppLocalizations.of(context)!;
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
                base.description ?? l10n.knowledge_description,
                style: Theme.of(context).textTheme.bodySmall,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
              const Spacer(),
              Text('${base.documentCount} ${l10n.knowledge_documents}', style: Theme.of(context).textTheme.labelSmall),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDocumentsList(BuildContext context, KnowledgeBaseModel base) {
    final l10n = AppLocalizations.of(context)!;
    final docsAsync = ref.watch(documentsProvider(base.id));

    return docsAsync.when(
      data: (docs) {
        if (docs.isEmpty) {
          return Center(child: Text(l10n.knowledge_no_documents));
        }

        return ListView.builder(
          padding: const EdgeInsets.symmetric(vertical: 4),
          itemCount: docs.length,
          itemBuilder: (context, index) {
            final doc = docs[index];
            return ListTile(
              leading: Icon(_getDocIcon(doc.contentType)),
              title: Text(doc.title),
              subtitle: Text('Added ${TimeFormatter.formatRelativeTime(doc.createdAt)}'),
              onTap: () => _openDocument(doc),
            );
          },
        );
      },
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (err, stack) => Center(child: Text('${l10n.error}: $err')),
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
    final l10n = AppLocalizations.of(context)!;
    if (_selectedBase == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.knowledge_enter_name)),
      );
      return;
    }

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.knowledge_upload_document),
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
          TextButton(onPressed: () => Navigator.pop(context), child: Text(l10n.cancel)),
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
    final l10n = AppLocalizations.of(context)!;
    final nameController = TextEditingController();
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.knowledge_create_base),
        content: TextField(
          controller: nameController,
          decoration: InputDecoration(labelText: l10n.knowledge_base_name),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: Text(l10n.cancel)),
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
            child: Text(l10n.create),
          ),
        ],
      ),
    );
  }
}