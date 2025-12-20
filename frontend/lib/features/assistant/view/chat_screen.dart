import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../provider/chat_provider.dart';
import '../models/chat_message_model.dart';
import '../../../core/constants/app_constants.dart';
import '../../../desktop/widgets/components/desktop_menu_bar.dart';

class ChatScreen extends ConsumerStatefulWidget {
  const ChatScreen({super.key});

  @override
  ConsumerState<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends ConsumerState<ChatScreen> {
  final _messageController = TextEditingController();
  final _scrollController = ScrollController();
  final _focusNode = FocusNode();
  bool _isComposing = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _focusNode.requestFocus();
    });
  }

  @override
  void dispose() {
    _messageController.dispose();
    _scrollController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  void _scrollToBottom() {
    if (_scrollController.hasClients) {
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeOut,
      );
    }
  }

  Future<void> _sendMessage() async {
    final text = _messageController.text.trim();
    if (text.isEmpty) return;

    final activeSessionId = ref.read(activeChatSessionIdProvider);
    if (activeSessionId == null) {
      // Create new session if none exists
      try {
        final newSession = await ref.read(chatSessionsProvider.notifier).createSession(
          title: text.length > 30 ? '${text.substring(0, 30)}...' : text,
        );
        ref.read(activeChatSessionIdProvider.notifier).state = newSession.id;

        // Send message to the new session
        await ref.read(chatSessionProvider(newSession.id).notifier).sendMessage(
          content: text,
        );
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
    } else {
      // Send message to existing session
      try {
        await ref.read(chatSessionProvider(activeSessionId).notifier).sendMessage(
          content: text,
        );
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to send message: ${e.toString()}'),
              backgroundColor: Theme.of(context).colorScheme.error,
            ),
          );
        }
      }
    }

    _messageController.clear();
    setState(() {
      _isComposing = false;
    });

    // Scroll to bottom after a short delay to allow UI to update
    Future.delayed(const Duration(milliseconds: 100), _scrollToBottom);
  }

  @override
  Widget build(BuildContext context) {
    final activeSessionId = ref.watch(activeChatSessionIdProvider);
    final chatSessionState = activeSessionId != null
        ? ref.watch(chatSessionProvider(activeSessionId))
        : null;

    return Scaffold(
      appBar: DesktopMenuBar(
        title: activeSessionId != null && chatSessionState?.session != null
            ? chatSessionState!.session!.title
            : 'New Chat',
        actions: [
          if (activeSessionId != null) ...[
            IconButton(
              onPressed: () {
                // TODO: Implement chat settings
              },
              icon: const Icon(Icons.settings_outlined),
              tooltip: 'Chat Settings',
            ),
            IconButton(
              onPressed: () {
                // TODO: Implement share chat
              },
              icon: const Icon(Icons.share_outlined),
              tooltip: 'Share Chat',
            ),
          ],
        ],
      ),
      body: Row(
        children: [
          // Chat List Sidebar (visible on larger screens)
          if (MediaQuery.of(context).size.width > 1400)
            SizedBox(
              width: 380,
              child: _buildChatList(),
            ),

          // Main Chat Area
          Expanded(
            child: Column(
              children: [
                // Messages Area
                Expanded(
                  child: activeSessionId != null
                      ? _buildMessageArea(chatSessionState)
                      : _buildWelcomeArea(),
                ),

                // Message Input Area
                _buildMessageInput(),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildChatList() {
    final chatSessionsState = ref.watch(chatSessionsProvider);

    return Column(
      children: [
        // Header
        Container(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              Expanded(
                child: Text(
                  'Conversations',
                  style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              IconButton.filled(
                onPressed: () async {
                  final newSession = await ref.read(chatSessionsProvider.notifier).createSession(
                    title: 'New Chat ${DateTime.now().toString().substring(5, 16)}',
                  );
                  ref.read(activeChatSessionIdProvider.notifier).state = newSession.id;
                },
                icon: const Icon(Icons.add),
                tooltip: 'New Chat',
              ),
            ],
          ),
        ),
        const Divider(height: 1),

        // Chat List
        Expanded(
          child: chatSessionsState.isLoading
              ? const Center(child: CircularProgressIndicator())
              : ListView.builder(
                  padding: const EdgeInsets.all(8),
                  itemCount: chatSessionsState.sessions.length,
                  itemBuilder: (context, index) {
                    final session = chatSessionsState.sessions[index];
                    final isActive = session.id == ref.read(activeChatSessionIdProvider);

                    return ChatListTile(
                      session: session,
                      isActive: isActive,
                      onTap: () {
                        ref.read(activeChatSessionIdProvider.notifier).state = session.id;
                      },
                    );
                  },
                ),
        ),
      ],
    );
  }

  Widget _buildMessageArea(ChatSessionState? chatSessionState) {
    if (chatSessionState == null) {
      return const Center(child: Text('Select a chat to start messaging'));
    }

    if (chatSessionState.isLoading && chatSessionState.messages.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }

    if (chatSessionState.messages.isEmpty) {
      return _buildEmptyChat();
    }

    return ListView.builder(
      controller: _scrollController,
      padding: const EdgeInsets.all(16),
      itemCount: chatSessionState.messages.length + (chatSessionState.isStreamingResponse ? 1 : 0),
      itemBuilder: (context, index) {
        if (index == chatSessionState.messages.length && chatSessionState.isStreamingResponse) {
          return const StreamingMessageWidget();
        }

        final message = chatSessionState.messages[index];
        return MessageWidget(message: message);
      },
    );
  }

  Widget _buildWelcomeArea() {
    return const ChatWelcomeScreen();
  }

  Widget _buildEmptyChat() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.chat_outlined,
            size: 80,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          const SizedBox(height: 16),
          Text(
            'Start a conversation',
            style: Theme.of(context).textTheme.titleLarge?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Type a message below to begin chatting with the AI assistant',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildMessageInput() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        border: Border(
          top: BorderSide(
            color: Theme.of(context).dividerColor,
            width: 1,
          ),
        ),
      ),
      child: Row(
        children: [
          // Attachment Button
          IconButton(
            onPressed: () {
              // TODO: Implement file attachment
            },
            icon: const Icon(Icons.attach_file_outlined),
            tooltip: 'Attach File',
          ),

          // Message Input
          Expanded(
            child: TextField(
              controller: _messageController,
              focusNode: _focusNode,
              maxLines: 5,
              minLines: 1,
              decoration: InputDecoration(
                hintText: 'Type your message...',
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(24),
                ),
                contentPadding: const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 12,
                ),
              ),
              onChanged: (text) {
                setState(() {
                  _isComposing = text.trim().isNotEmpty;
                });
              },
              onSubmitted: (_) => _sendMessage(),
            ),
          ),

          const SizedBox(width: 8),

          // Send Button
          IconButton.filled(
            onPressed: _isComposing && !ref.watch(chatSessionProvider(ref.watch(activeChatSessionIdProvider) ?? '')).isLoading
                ? _sendMessage
                : null,
            icon: const Icon(Icons.send),
            tooltip: 'Send Message',
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
    required this.isActive,
    required this.onTap,
  });

  final dynamic session; // Replace with proper ChatSessionModel type
  final bool isActive;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      color: isActive ? Theme.of(context).colorScheme.primaryContainer : null,
      child: ListTile(
        onTap: onTap,
        leading: CircleAvatar(
          backgroundColor: isActive
              ? Theme.of(context).colorScheme.onPrimaryContainer
              : Theme.of(context).colorScheme.primaryContainer,
          child: Icon(
            Icons.chat,
            color: isActive
                ? Theme.of(context).colorScheme.primaryContainer
                : Theme.of(context).colorScheme.onPrimaryContainer,
          ),
        ),
        title: Text(
          session.title,
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
            color: isActive
                ? Theme.of(context).colorScheme.onPrimaryContainer
                : null,
          ),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
        subtitle: Text(
          '${session.messageCount} messages • ${session.formattedLastMessageAt}',
          style: Theme.of(context).textTheme.bodySmall?.copyWith(
            color: isActive
                ? Theme.of(context).colorScheme.onPrimaryContainer.withValues(alpha: 0.8)
                : Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
      ),
    );
  }
}

class MessageWidget extends StatelessWidget {
  const MessageWidget({super.key, required this.message});

  final ChatMessageModel message;

  @override
  Widget build(BuildContext context) {
    final isUser = message.isUser;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        mainAxisAlignment: isUser ? MainAxisAlignment.end : MainAxisAlignment.start,
        children: [
          if (!isUser) ...[
            CircleAvatar(
              radius: 16,
              backgroundColor: Theme.of(context).colorScheme.primaryContainer,
              child: Icon(
                Icons.smart_toy,
                color: Theme.of(context).colorScheme.onPrimaryContainer,
                size: 20,
              ),
            ),
            const SizedBox(width: 8),
          ],
          Flexible(
            child: Container(
              constraints: BoxConstraints(
                maxWidth: MediaQuery.of(context).size.width * 0.7,
              ),
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: isUser
                    ? Theme.of(context).colorScheme.primaryContainer
                    : Theme.of(context).colorScheme.surface,
                borderRadius: BorderRadius.circular(16),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    message.content,
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                      color: isUser
                          ? Theme.of(context).colorScheme.onPrimaryContainer
                          : Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '${message.createdAt.hour.toString().padLeft(2, '0')}:${message.createdAt.minute.toString().padLeft(2, '0')}',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: isUser
                          ? Theme.of(context).colorScheme.onPrimaryContainer.withValues(alpha: 0.7)
                          : Theme.of(context).colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
                    ),
                  ),
                ],
              ),
            ),
          ),
          if (isUser) ...[
            const SizedBox(width: 8),
            CircleAvatar(
              radius: 16,
              backgroundColor: Theme.of(context).colorScheme.primary,
              child: const Icon(
                Icons.person,
                color: Colors.white,
                size: 20,
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class StreamingMessageWidget extends StatelessWidget {
  const StreamingMessageWidget({super.key});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        children: [
          CircleAvatar(
            radius: 16,
            backgroundColor: Theme.of(context).colorScheme.primaryContainer,
            child: Icon(
              Icons.smart_toy,
              color: Theme.of(context).colorScheme.onPrimaryContainer,
              size: 20,
            ),
          ),
          const SizedBox(width: 8),
          Container(
            constraints: BoxConstraints(
              maxWidth: MediaQuery.of(context).size.width * 0.7,
            ),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surface,
              borderRadius: BorderRadius.circular(16),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
                const SizedBox(width: 8),
                Text(
                  'AI is thinking...',
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}