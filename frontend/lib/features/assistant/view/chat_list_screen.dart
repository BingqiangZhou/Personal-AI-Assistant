import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../provider/chat_provider.dart';
import '../models/chat_session_model.dart';
import '../../../core/constants/app_constants.dart';
import '../../../desktop/widgets/components/desktop_menu_bar.dart';

class ChatListScreen extends ConsumerStatefulWidget {
  const ChatListScreen({super.key});

  @override
  ConsumerState<ChatListScreen> createState() => _ChatListScreenState();
}

class _ChatListScreenState extends ConsumerState<ChatListScreen> {
  final TextEditingController _searchController = TextEditingController();

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _createNewChat() async {
    try {
      final chatNotifier = ref.read(chatSessionsProvider.notifier);
      final newSession = await chatNotifier.createSession(
        title: 'New Chat ${DateTime.now().toString().substring(5, 16)}',
      );

      if (mounted) {
        context.go('/chat/${newSession.id}');
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to create chat: ${e.toString()}'),
            backgroundColor: Theme.of(context).colorScheme.error,
          ),
        );
      }
    }
  }

  Future<void> _deleteChat(String sessionId) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete Chat'),
        content: const Text('Are you sure you want to delete this chat? This action cannot be undone.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      try {
        await ref.read(chatSessionsProvider.notifier).deleteSession(sessionId);
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to delete chat: ${e.toString()}'),
              backgroundColor: Theme.of(context).colorScheme.error,
            ),
          );
        }
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final chatSessionsState = ref.watch(chatSessionsProvider);
    final screenWidth = MediaQuery.of(context).size.width;

    return Scaffold(
      appBar: DesktopMenuBar(
        title: 'AI Assistant',
        actions: [
          IconButton(
            onPressed: () {
              // TODO: Implement settings
            },
            icon: const Icon(Icons.settings_outlined),
            tooltip: 'Settings',
          ),
        ],
      ),
      body: Row(
        children: [
          // Chat List Sidebar
          SizedBox(
            width: screenWidth > 1200 ? 380 : 320,
            child: Column(
              children: [
                // Header
                Container(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    children: [
                      Row(
                        children: [
                          Expanded(
                            child: TextField(
                              controller: _searchController,
                              decoration: InputDecoration(
                                hintText: 'Search conversations...',
                                prefixIcon: const Icon(Icons.search),
                                border: OutlineInputBorder(
                                  borderRadius: BorderRadius.circular(12),
                                ),
                                contentPadding: const EdgeInsets.symmetric(
                                  horizontal: 16,
                                  vertical: 8,
                                ),
                              ),
                              onChanged: (value) {
                                // TODO: Implement search
                              },
                            ),
                          ),
                          const SizedBox(width: 8),
                          IconButton.filled(
                            onPressed: _createNewChat,
                            icon: const Icon(Icons.add),
                            tooltip: 'New Chat',
                          ),
                        ],
                      ),
                    ],
                  ),
                ),

                // Chat List
                Expanded(
                  child: chatSessionsState.isLoading
                      ? const Center(child: CircularProgressIndicator())
                      : chatSessionsState.sessions.isEmpty
                          ? Center(
                              child: Column(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  Icon(
                                    Icons.chat_outlined,
                                    size: 64,
                                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                                  ),
                                  const SizedBox(height: 16),
                                  Text(
                                    'No conversations yet',
                                    style: Theme.of(context).textTheme.titleMedium?.copyWith(
                                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                                    ),
                                  ),
                                  const SizedBox(height: 8),
                                  Text(
                                    'Start a new conversation to get started',
                                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                                    ),
                                  ),
                                  const SizedBox(height: 16),
                                  ElevatedButton.icon(
                                    onPressed: _createNewChat,
                                    icon: const Icon(Icons.add),
                                    label: const Text('Start New Chat'),
                                  ),
                                ],
                              ),
                            )
                          : ListView.builder(
                              padding: const EdgeInsets.all(8),
                              itemCount: chatSessionsState.sessions.length,
                              itemBuilder: (context, index) {
                                final session = chatSessionsState.sessions[index];
                                return ChatListTile(
                                  session: session,
                                  onTap: () {
                                    context.go('/chat/${session.id}');
                                  },
                                  onDelete: () => _deleteChat(session.id),
                                );
                              },
                            ),
                ),
              ],
            ),
          ),

          // Main Content Area
          const Expanded(
            child: ChatWelcomeScreen(),
          ),
        ],
      ),
    );
  }
}

class ChatListTile extends StatelessWidget {
  const ChatListTile({
    super.key,
    required this.session,
    required this.onTap,
    required this.onDelete,
  });

  final ChatSessionModel session;
  final VoidCallback onTap;
  final VoidCallback onDelete;

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      child: ListTile(
        onTap: onTap,
        leading: CircleAvatar(
          backgroundColor: Theme.of(context).colorScheme.primaryContainer,
          child: Icon(
            Icons.chat,
            color: Theme.of(context).colorScheme.onPrimaryContainer,
          ),
        ),
        title: Text(
          session.title,
          style: Theme.of(context).textTheme.titleMedium,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
        subtitle: Text(
          '${session.messageCount} messages • ${session.formattedLastMessageAt}',
          style: Theme.of(context).textTheme.bodySmall?.copyWith(
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
        trailing: PopupMenuButton<String>(
          icon: const Icon(Icons.more_vert),
          itemBuilder: (context) => [
            const PopupMenuItem(
              value: 'rename',
              child: Row(
                children: [
                  Icon(Icons.edit_outlined),
                  SizedBox(width: 8),
                  Text('Rename'),
                ],
              ),
            ),
            const PopupMenuItem(
              value: 'delete',
              child: Row(
                children: [
                  Icon(Icons.delete_outline, color: Colors.red),
                  SizedBox(width: 8),
                  Text('Delete', style: TextStyle(color: Colors.red)),
                ],
              ),
            ),
          ],
          onSelected: (value) {
            switch (value) {
              case 'rename':
                // TODO: Implement rename
                break;
              case 'delete':
                onDelete();
                break;
            }
          },
        ),
      ),
    );
  }
}

class ChatWelcomeScreen extends ConsumerWidget {
  const ChatWelcomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.smart_toy,
            size: 120,
            color: Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(height: 24),
          Text(
            'Welcome to ${AppConstants.appName}',
            style: Theme.of(context).textTheme.headlineLarge?.copyWith(
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Your intelligent AI assistant for knowledge and conversation',
            style: Theme.of(context).textTheme.bodyLarge?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 48),
          Wrap(
            spacing: 16,
            runSpacing: 16,
            children: [
              _buildFeatureCard(
                context,
                icon: Icons.chat,
                title: 'Start Conversation',
                description: 'Chat with AI assistant for answers and assistance',
                onTap: () {
                  // Create new chat
                  final chatNotifier = ref.read(chatSessionsProvider.notifier);
                  chatNotifier.createSession(
                    title: 'New Chat ${DateTime.now().toString().substring(5, 16)}',
                  ).then((session) {
                    if (context.mounted) {
                      context.go('/chat/${session.id}');
                    }
                  });
                },
              ),
              _buildFeatureCard(
                context,
                icon: Icons.library_books,
                title: 'Knowledge Base',
                description: 'Access and manage your knowledge repository',
                onTap: () {
                  context.go('/knowledge');
                },
              ),
              _buildFeatureCard(
                context,
                icon: Icons.rss_feed,
                title: 'Subscriptions',
                description: 'Stay updated with your favorite content sources',
                onTap: () {
                  context.go('/subscriptions');
                },
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildFeatureCard(
    BuildContext context, {
    required IconData icon,
    required String title,
    required String description,
    required VoidCallback onTap,
  }) {
    return Card(
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(12),
        child: Container(
          width: 280,
          padding: const EdgeInsets.all(24),
          child: Column(
            children: [
              Icon(
                icon,
                size: 48,
                color: Theme.of(context).colorScheme.primary,
              ),
              const SizedBox(height: 16),
              Text(
                title,
                style: Theme.of(context).textTheme.titleMedium?.copyWith(
                  fontWeight: FontWeight.bold,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              Text(
                description,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      ),
    );
  }
}