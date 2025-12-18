import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../knowledge/presentation/pages/knowledge_base_page.dart';

/// Desktop version of knowledge list screen
class KnowledgeListScreen extends ConsumerStatefulWidget {
  const KnowledgeListScreen({super.key});

  @override
  ConsumerState<KnowledgeListScreen> createState() => _KnowledgeListScreenState();
}

class _KnowledgeListScreenState extends ConsumerState<KnowledgeListScreen> {
  @override
  Widget build(BuildContext context) {
    // For now, reuse the mobile knowledge base page
    // This can be enhanced with desktop-specific layout later
    return const KnowledgeBasePage();
  }
}
