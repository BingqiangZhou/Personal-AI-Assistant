import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../data/models/podcast_conversation_model.dart';
import '../../data/models/podcast_playback_model.dart';
import '../providers/conversation_providers.dart';
import '../providers/summary_providers.dart';

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
  ConsumerState<ConversationChatWidget> createState() => ConversationChatWidgetState();
}

class ConversationChatWidgetState extends ConsumerState<ConversationChatWidget> {
  final TextEditingController _messageController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  final FocusNode _focusNode = FocusNode();
  SummaryModelInfo? _selectedModel;

  /// 滚动到顶部
  void scrollToTop() {
    if (_scrollController.hasClients) {
      _scrollController.animateTo(
        0.0,
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeInOut,
      );
    }
  }

  @override
  void initState() {
    super.initState();
    _focusNode.addListener(() {
      if (_focusNode.hasFocus) {
        // Scroll to bottom when keyboard appears
        Future.delayed(const Duration(milliseconds: 300), _scrollToBottom);
      }
    });
    // 自动选择默认模型
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final modelsAsync = ref.read(availableModelsProvider);
      modelsAsync.when(
        data: (models) {
          if (models.isNotEmpty) {
            final defaultModel = models.firstWhere(
              (m) => m.isDefault,
              orElse: () => models.first,
            );
            if (mounted) {
              setState(() => _selectedModel = defaultModel);
            }
          }
        },
        loading: () {},
        error: (_, __) {},
      );
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
    notifier.sendMessage(message, modelName: _selectedModel?.name);

    _messageController.clear();
    _focusNode.requestFocus();
  }

  void _clearHistory() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) {
        final l10n = AppLocalizations.of(context)!;
        return AlertDialog(
          title: Text(l10n.podcast_conversation_clear_history),
          content: Text(l10n.podcast_conversation_clear_confirm),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: Text(l10n.cancel),
            ),
            TextButton(
              onPressed: () => Navigator.pop(context, true),
              style: TextButton.styleFrom(
                foregroundColor: Theme.of(context).colorScheme.error,
              ),
              child: Text(l10n.podcast_transcription_clear),
            ),
          ],
        );
      },
    );

    if (confirmed == true && mounted) {
      await ref.read(getConversationProvider(widget.episodeId).notifier).clearHistory();
    }
  }

  void _startNewChat() async {
    final l10n = AppLocalizations.of(context)!;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: Text(l10n.podcast_conversation_new_chat),
          content: Text(l10n.podcast_conversation_new_chat_confirm),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: Text(l10n.cancel),
            ),
            FilledButton.tonal(
              onPressed: () => Navigator.pop(context, true),
              child: Text(l10n.podcast_conversation_new_chat),
            ),
          ],
        );
      },
    );

    if (confirmed == true && mounted) {
      await ref.read(getConversationProvider(widget.episodeId).notifier).startNewChat();
      _messageController.clear();
      _focusNode.requestFocus();
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

    return Scaffold(
      backgroundColor: Colors.transparent,
      endDrawer: _buildSessionsDrawer(context),
      body: Column(
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
      ),
    );
  }

  Widget _buildSessionsDrawer(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final sessionsAsync = ref.watch(getSessionListProvider(widget.episodeId));
    final currentSessionId = ref.watch(getCurrentSessionIdProvider(widget.episodeId));

    return Drawer(
      width: MediaQuery.of(context).size.width * 0.75,
      child: Column(
        children: [
          DrawerHeader(
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surfaceContainerHighest,
            ),
            child: Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    Icons.history,
                    size: 48,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                  const SizedBox(height: 16),
                  Text(
                    l10n.podcast_conversation_history,
                    style: Theme.of(context).textTheme.titleLarge,
                  ),
                ],
              ),
            ),
          ),
          Expanded(
            child: sessionsAsync.when(
              data: (sessions) {
                if (sessions.isEmpty) {
                  return Center(
                    child: Text(
                      l10n.podcast_conversation_empty_title,
                      style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                            color: Theme.of(context).colorScheme.onSurfaceVariant,
                          ),
                    ),
                  );
                }
                return ListView.builder(
                  padding: EdgeInsets.zero,
                  itemCount: sessions.length,
                  itemBuilder: (context, index) {
                    final session = sessions[index];
                    final isSelected = session.id == currentSessionId;
                    return ListTile(
                      leading: Icon(
                        isSelected
                            ? Icons.chat_bubble
                            : Icons.chat_bubble_outline,
                        color: isSelected
                            ? Theme.of(context).colorScheme.primary
                            : null,
                      ),
                      title: Text(
                        session.title,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                          color: isSelected
                              ? Theme.of(context).colorScheme.primary
                              : null,
                          fontWeight:
                              isSelected ? FontWeight.bold : FontWeight.normal,
                        ),
                      ),
                      subtitle: Text(
                        session.createdAt.substring(0, 10), // Simple date format
                        style: Theme.of(context).textTheme.labelSmall,
                      ),
                      trailing: IconButton(
                        icon: const Icon(Icons.delete_outline, size: 20),
                        onPressed: () async {
                          final confirm = await showDialog<bool>(
                            context: context,
                            builder: (context) => AlertDialog(
                              title: Text(l10n.podcast_conversation_delete_title),
                              content: Text(
                                  l10n.podcast_conversation_delete_confirm),
                              actions: [
                                TextButton(
                                  onPressed: () =>
                                      Navigator.pop(context, false),
                                  child: Text(l10n.cancel),
                                ),
                                TextButton(
                                  onPressed: () =>
                                      Navigator.pop(context, true),
                                  child: Text(
                                    l10n.delete,
                                    style: TextStyle(
                                      color: Theme.of(context)
                                          .colorScheme
                                          .error,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          );
                          if (confirm == true) {
                            ref
                                .read(getSessionListProvider(widget.episodeId)
                                    .notifier)
                                .deleteSession(session.id);
                          }
                        },
                      ),
                      selected: isSelected,
                      onTap: () {
                        ref
                            .read(getCurrentSessionIdProvider(widget.episodeId)
                                .notifier)
                            .set(session.id);
                        Navigator.pop(context); // Close drawer
                      },
                    );
                  },
                );
              },
              loading: () => const Center(child: CircularProgressIndicator()),
              error: (e, __) => Center(child: Text('Error: $e')),
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(16.0),
            child: SizedBox(
              width: double.infinity,
              child: FilledButton.icon(
                onPressed: () {
                  Navigator.pop(context); // Close drawer first
                  _startNewChat();
                },
                icon: const Icon(Icons.add),
                label: Text(l10n.podcast_conversation_new_chat),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildHeader(BuildContext context, ConversationState state) {
    final l10n = AppLocalizations.of(context)!;
    final availableModelsAsync = ref.watch(availableModelsProvider);
    final messageCount = state.messages.length;
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
            child: Row(
              children: [
                Flexible(
                  child: Text(
                    l10n.podcast_conversation_title,
                    style: Theme.of(context).textTheme.titleMedium?.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                if (messageCount > 0) ...[
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.primaryContainer,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Text(
                      l10n.podcast_conversation_message_count(messageCount),
                      style: Theme.of(context).textTheme.labelSmall?.copyWith(
                            color: Theme.of(context).colorScheme.onPrimaryContainer,
                          ),
                    ),
                  ),
                ],
              ],
            ),
          ),
          // 模型选择器
          availableModelsAsync.when(
            data: (models) {
              if (models.length <= 1) return const SizedBox.shrink();
              return _buildModelSelector(context, models);
            },
            loading: () => const SizedBox.shrink(),
            error: (_, __) => const SizedBox.shrink(),
          ),
          if (state.hasMessages)
            IconButton(
              icon: const Icon(Icons.add_comment_outlined),
              tooltip: l10n.podcast_conversation_new_chat,
              onPressed: state.isSending ? null : _startNewChat,
            ),
          Builder(
            builder: (context) => IconButton(
              icon: const Icon(Icons.history),
              tooltip: l10n.podcast_conversation_history,
              onPressed: () {
                Scaffold.of(context).openEndDrawer();
              },
            ),
          ),
          if (state.hasError)
            IconButton(
              icon: const Icon(Icons.refresh),
              tooltip: l10n.podcast_conversation_reload,
              onPressed: state.isSending
                  ? null
                  : () => ref.read(getConversationProvider(widget.episodeId).notifier).refresh(),
            ),
        ],
      ),
    );
  }

  Widget _buildModelSelector(BuildContext context, List<SummaryModelInfo> models) {
    final l10n = AppLocalizations.of(context)!;
    // 确保_selectedModel在可用列表中
    if (_selectedModel != null && !models.any((m) => m.id == _selectedModel!.id)) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) {
          setState(() {
            _selectedModel = models.firstWhere(
              (m) => m.isDefault,
              orElse: () => models.first,
            );
          });
        }
      });
    }
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(8),
      ),
      child: DropdownButton<SummaryModelInfo>(
        value: _selectedModel,
        underline: const SizedBox.shrink(),
        isDense: true,
        icon: const Icon(Icons.expand_more, size: 18),
        hint: Text(
          l10n.podcast_ai_model,
          style: Theme.of(context).textTheme.bodySmall,
        ),
        style: Theme.of(context).textTheme.bodySmall?.copyWith(
              color: Theme.of(context).colorScheme.onSurface,
            ),
        items: models.map((model) {
          return DropdownMenuItem<SummaryModelInfo>(
            value: model,
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(model.displayName),
                if (model.isDefault)
                  Padding(
                    padding: const EdgeInsets.only(left: 6),
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 4,
                        vertical: 1,
                      ),
                      decoration: BoxDecoration(
                        color: Theme.of(context)
                            .colorScheme
                            .primary
                            .withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Text(
                        l10n.podcast_default_model,
                        style: TextStyle(
                          fontSize: 10,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                      ),
                    ),
                  ),
              ],
            ),
          );
        }).toList(),
        onChanged: (value) {
          setState(() => _selectedModel = value);
        },
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
              AppLocalizations.of(context)!.podcast_conversation_loading_failed,
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
    final l10n = AppLocalizations.of(context)!;
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
              l10n.podcast_conversation_empty_title,
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            Text(
              l10n.podcast_conversation_empty_hint,
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
                          AppLocalizations.of(context)!.podcast_filter_with_summary,
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
                  isUser ? AppLocalizations.of(context)!.podcast_conversation_user : AppLocalizations.of(context)!.podcast_conversation_assistant,
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
    final l10n = AppLocalizations.of(context)!;
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
                      ? l10n.podcast_conversation_no_summary_hint
                      : l10n.podcast_conversation_send_hint,
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
