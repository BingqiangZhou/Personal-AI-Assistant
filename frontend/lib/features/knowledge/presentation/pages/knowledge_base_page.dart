import 'package:flutter/material.dart';

class KnowledgeBasePage extends StatelessWidget {
  const KnowledgeBasePage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Knowledge Base'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          children: [
            // Search bar
            TextField(
              decoration: InputDecoration(
                hintText: 'Search your knowledge base...',
                prefixIcon: const Icon(Icons.search),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
                contentPadding: const EdgeInsets.symmetric(vertical: 12),
              ),
            ),
            const SizedBox(height: 16),

            // Stats cards
            Row(
              children: [
                Expanded(
                  child: Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        children: [
                          const Icon(Icons.description, size: 32),
                          const SizedBox(height: 8),
                          const Text('Documents', style: TextStyle(fontWeight: FontWeight.bold)),
                          Text('0', style: Theme.of(context).textTheme.headlineSmall),
                        ],
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        children: [
                          const Icon(Icons.folder, size: 32),
                          const SizedBox(height: 8),
                          const Text('Categories', style: TextStyle(fontWeight: FontWeight.bold)),
                          Text('0', style: Theme.of(context).textTheme.headlineSmall),
                        ],
                      ),
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),

            // Content area
            Expanded(
              child: Center(
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(
                      Icons.library_books,
                      size: 80,
                      color: Colors.grey.shade400,
                    ),
                    const SizedBox(height: 16),
                    Text(
                      'Your Knowledge Base',
                      style: Theme.of(context).textTheme.headlineSmall,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Add documents to build your personal knowledge library',
                      style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                        color: Colors.grey.shade600,
                      ),
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 24),
                    ElevatedButton.icon(
                      onPressed: () {
                        // TODO: Add document
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Feature coming soon!')),
                        );
                      },
                      icon: const Icon(Icons.add),
                      label: const Text('Add Document'),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}