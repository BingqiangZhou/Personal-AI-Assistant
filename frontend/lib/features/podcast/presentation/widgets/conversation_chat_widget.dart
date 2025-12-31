import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../data/models/podcast_conversation_model.dart';
import '../providers/conversation_providers.dart';

/// AI对话聊天界面组件
class ConversationChatWidget extends ConsumerStatefulWidget {
  final int episodeId;
  final String? aiSummary;

  const ConversationChatWidget({
    super.key,
    required this.episodeId,
    this.aiSummary,
  });

  @override
  ConsumerState<ConversationChatWidget> createState() => _ConversationChatWidgetState();
}

class _ConversationChatWidgetState extends ConsumerState<ConversationChatWidget> {
  final TextEditingController _messageController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  final FocusNode _focusNode = FocusNode();

  @override
  void initState() {
    super.initState();
    _focusNode.addListener(() {
      if (_focusNode.hasFocus) {
        // Scroll to bottom when keyboard appears
        Future.delayed(const Duration(milliseconds: 300), _scrollToBottom);
      }
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
    if (_scrollController.hasClients && _scrollController.position.maxScrollExtent > 0) {
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeOut,
      );
    }
  }

  void _sendMessage() {
    final message = _messageController.text.trim();
    if (message.isEmpty) return;

    final notifier = ref.read(getConversationProvider(widget.episodeId).notifier);
    notifier.sendMessage(message);

    _messageController.clear();
    _focusNode.requestFocus();
  }

  void _clearHistory() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Clear conversation history'),
        content: const Text('Are you sure you want to clear all conversation history? This action cannot be undone.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            style: TextButton.styleFrom(
              foregroundColor: Theme.of(context).colorScheme.error,
            ),
            child: const Text('Clear'),
          ),
        ],
      ),
    );

    if (confirmed == true && mounted) {
      await ref.read(getConversationProvider(widget.episodeId).notifier).clearHistory();
    }
  }

  @override
  Widget build(BuildContext context) {
    final conversationState = ref.watch(getConversationProvider(widget.episodeId));

    // Scroll to bottom when new messages arrive
    ref.listen<ConversationState>(
      getConversationProvider(widget.episodeId),
      (previous, next) {
        if (next.messages.length > (previous?.messages.length ?? 0)) {
          Future.delayed(const Duration(milliseconds: 100), _scrollToBottom);
        }
      },
    );

    return Column(
      children: [
        // Header with title and actions
        _buildHeader(context, conversationState),

        // Messages list
        Expanded(
          child: _buildMessagesList(context, conversationState),
        ),

        // Input field
        _buildInputArea(context, conversationState),
      ],
    );
  }

  Widget _buildHeader(BuildContext context, ConversationState state) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        border: Border(
          bottom: BorderSide(
            color: Theme.of(context).colorScheme.outlineVariant,
            width: 1,
          ),
        ),
      ),
      child: Row(
        children: [
          const Icon(Icons.chat_bubble_outline),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              'AI Assistant Chat',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w600,
                  ),
            ),
          ),
          if (state.hasMessages)
            IconButton(
              icon: const Icon(Icons.delete_outline),
              tooltip: 'Clear conversation history',
              onPressed: state.isSending ? null : _clearHistory,
            ),
          if (state.hasError)
            IconButton(
              icon: const Icon(Icons.refresh),
              tooltip: 'Reload',
              onPressed: state.isSending
                  ? null
                  : () => ref.read(getConversationProvider(widget.episodeId).notifier).refresh(),
            ),
        ],
      ),
    );
  }

  Widget _buildMessagesList(BuildContext context, ConversationState state) {
    if (state.isLoading) {
      return const Center(
        child: CircularProgressIndicator(),
      );
    }

    if (state.hasError) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.error_outline,
              size: 64,
              color: Theme.of(context).colorScheme.error,
            ),
            const SizedBox(height: 16),
            Text(
              'Failed to load conversation',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              state.errorMessage ?? '',
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
            ),
          ],
        ),
      );
    }

    if (state.isEmpty) {
      return _buildEmptyState(context);
    }

    return ListView.separated(
      controller: _scrollController,
      padding: const EdgeInsets.all(16),
      itemCount: state.messages.length,
      separatorBuilder: (context, index) => const SizedBox(height: 16),
      itemBuilder: (context, index) {
        final message = state.messages[index];
        return _buildMessageBubble(context, message);
      },
    );
  }

  Widget _buildEmptyState(BuildContext context) {
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(32),
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
              'Chat with AI Assistant',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            Text(
              'You can ask the AI assistant questions based on this episode\'s AI summary',
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            if (widget.aiSummary != null && widget.aiSummary!.isNotEmpty)
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(
                    color: Theme.of(context).colorScheme.outlineVariant,
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(
                          Icons.summarize_outlined,
                          size: 16,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          'AI Summary',
                          style: Theme.of(context).textTheme.labelMedium?.copyWith(
                                color: Theme.of(context).colorScheme.primary,
                                fontWeight: FontWeight.w600,
                              ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Text(
                      widget.aiSummary!.length > 200
                          ? '${widget.aiSummary!.substring(0, 200)}...'
                          : widget.aiSummary!,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: Theme.of(context).colorScheme.onSurfaceVariant,
                            height: 1.5,
                          ),
                    ),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildMessageBubble(BuildContext context, PodcastConversationMessage message) {
    final isUser = message.isUser;

    return Align(
      alignment: isUser ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        constraints: BoxConstraints(
          maxWidth: MediaQuery.of(context).size.width * 0.75,
        ),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        decoration: BoxDecoration(
          color: isUser
              ? Theme.of(context).colorScheme.primaryContainer
              : Theme.of(context).colorScheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: isUser
                ? Theme.of(context).colorScheme.primary.withValues(alpha: 0.3)
                : Theme.of(context).colorScheme.outlineVariant.withValues(alpha: 0.3),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Message header with role and time
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  isUser ? Icons.person_outline : Icons.smart_toy_outlined,
                  size: 14,
                  color: isUser
                      ? Theme.of(context).colorScheme.onPrimaryContainer
                      : Theme.of(context).colorScheme.onSurfaceVariant,
                ),
                const SizedBox(width: 4),
                Text(
                  isUser ? 'You' : 'AI Assistant',
                  style: Theme.of(context).textTheme.labelSmall?.copyWith(
                        color: isUser
                            ? Theme.of(context).colorScheme.onPrimaryContainer
                            : Theme.of(context).colorScheme.onSurfaceVariant,
                        fontWeight: FontWeight.w600,
                      ),
                ),
              ],
            ),
            const SizedBox(height: 6),
            // Message content
            SelectableText(
              message.content,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: isUser
                        ? Theme.of(context).colorScheme.onPrimaryContainer
                        : Theme.of(context).colorScheme.onSurface,
                    height: 1.5,
                  ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInputArea(BuildContext context, ConversationState state) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        border: Border(
          top: BorderSide(
            color: Theme.of(context).colorScheme.outlineVariant,
            width: 1,
          ),
        ),
      ),
      child: SafeArea(
        top: false,
        child: Row(
          children: [
            Expanded(
              child: TextField(
                controller: _messageController,
                focusNode: _focusNode,
                enabled: state.isReady && widget.aiSummary != null,
                maxLines: null,
                minLines: 1,
                textInputAction: TextInputAction.send,
                onSubmitted: (_) => _sendMessage(),
                decoration: InputDecoration(
                  hintText: widget.aiSummary == null
                      ? 'Please generate AI summary first'
                      : 'Type your question...',
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(24),
                    borderSide: BorderSide(
                      color: Theme.of(context).colorScheme.outline,
                    ),
                  ),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(24),
                    borderSide: BorderSide(
                      color: Theme.of(context).colorScheme.outline,
                    ),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(24),
                    borderSide: BorderSide(
                      color: Theme.of(context).colorScheme.primary,
                      width: 2,
                    ),
                  ),
                  contentPadding: const EdgeInsets.symmetric(
                    horizontal: 20,
                    vertical: 12,
                  ),
                ),
              ),
            ),
            const SizedBox(width: 8),
            IconButton.filled(
              onPressed: (state.isReady &&
                      _messageController.text.trim().isNotEmpty &&
                      widget.aiSummary != null)
                  ? _sendMessage
                  : null,
              icon: state.isSending
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                      ),
                    )
                  : const Icon(Icons.send),
              style: IconButton.styleFrom(
                padding: const EdgeInsets.all(12),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
