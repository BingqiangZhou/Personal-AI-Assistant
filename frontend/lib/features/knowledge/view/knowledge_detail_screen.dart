import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Desktop version of knowledge detail screen
class KnowledgeDetailScreen extends ConsumerStatefulWidget {
  final String knowledgeId;

  const KnowledgeDetailScreen({
    super.key,
    required this.knowledgeId,
  });

  @override
  ConsumerState<KnowledgeDetailScreen> createState() => _KnowledgeDetailScreenState();
}

class _KnowledgeDetailScreenState extends ConsumerState<KnowledgeDetailScreen> {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Knowledge Detail: ${widget.knowledgeId}'),
      ),
      body: Center(
        child: Text('Detail view for knowledge item: ${widget.knowledgeId}'),
      ),
    );
  }
}
