import 'package:flutter/material.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/widgets/custom_adaptive_navigation.dart';

/// Material Design 3自适应AI Assistant页面
class AssistantChatPage extends StatefulWidget {
  const AssistantChatPage({super.key});

  @override
  State<AssistantChatPage> createState() => _AssistantChatPageState();
}

class _AssistantChatPageState extends State<AssistantChatPage> {
  final TextEditingController _controller = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  final List<ChatMessage> _messages = [
    ChatMessage(
      content: '你好！我是你的AI助手。我可以帮助你回答问题、提供建议、生成内容等。有什么我可以帮助你的吗？',
      isUser: false,
      timestamp: DateTime.now().subtract(const Duration(minutes: 5)),
    ),
  ];

  @override
  void dispose() {
    _controller.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return ResponsiveContainer(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // 页面标题和操作区域
          SizedBox(
            height: 56,
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    l10n.nav_assistant,
                    style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                  ),
                ),
                const SizedBox(width: 16),
                Row(
                  children: [
                    // 清除对话按钮
                    FilledButton.tonal(
                      onPressed: () {
                        _showClearChatDialog(context);
                      },
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const Icon(Icons.clear, size: 16),
                          const SizedBox(width: 4),
                          Text(l10n.chat_clear_history),
                        ],
                      ),
                    ),
                    const SizedBox(width: 12),
                    // 设置按钮
                    IconButton.filled(
                      onPressed: () {
                        _showSettingsDialog(context);
                      },
                      icon: const Icon(Icons.settings),
                      tooltip: l10n.nav_settings,
                    ),
                  ],
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),

          // AI模型选择栏
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Row(
              children: [
                // AI模型选择器
                Expanded(
                  child: DropdownButtonFormField<String>(
                    value: 'claude-3-5-sonnet',
                    decoration: InputDecoration(
                      labelText: l10n.assistant_model,
                      prefixIcon: const Icon(Icons.psychology),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                    ),
                    items: const [
                      DropdownMenuItem(
                        value: 'claude-3-5-sonnet',
                        child: Text('Claude 3.5 Sonnet'),
                      ),
                      DropdownMenuItem(
                        value: 'claude-3-opus',
                        child: Text('Claude 3 Opus'),
                      ),
                      DropdownMenuItem(
                        value: 'claude-3-haiku',
                        child: Text('Claude 3 Haiku'),
                      ),
                      DropdownMenuItem(
                        value: 'gpt-4-turbo',
                        child: Text('GPT-4 Turbo'),
                      ),
                    ],
                    onChanged: (value) {
                      // TODO: 实现模型切换逻辑
                    },
                  ),
                ),
                const SizedBox(width: 16),
                // 对话模式选择
                IconButton.filled(
                  onPressed: () {
                    _showModeSelector(context);
                  },
                  icon: const Icon(Icons.chat),
                  tooltip: 'Chat Mode',
                ),
              ],
            ),
          ),

          const SizedBox(height: 24),

          // 聊天内容区域
          Expanded(
            child: Container(
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surface,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.2),
                ),
              ),
              child: Column(
                children: [
                  // 消息列表
                  Expanded(
                    child: ListView.builder(
                      controller: _scrollController,
                      padding: const EdgeInsets.all(16),
                      itemCount: _messages.length,
                      itemBuilder: (context, index) {
                        return _buildMessageBubble(_messages[index]);
                      },
                    ),
                  ),

                  // 输入区域
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
                      borderRadius: const BorderRadius.only(
                        bottomLeft: Radius.circular(12),
                        bottomRight: Radius.circular(12),
                      ),
                    ),
                    child: Row(
                      children: [
                        // 附件按钮
                        IconButton.filled(
                          onPressed: () {
                            _showAttachmentOptions(context);
                          },
                          icon: const Icon(Icons.attach_file),
                          tooltip: 'Attach File',
                          style: IconButton.styleFrom(
                            backgroundColor: Theme.of(context).colorScheme.surfaceContainerHighest,
                            foregroundColor: Theme.of(context).colorScheme.onSurfaceVariant,
                          ),
                        ),
                        const SizedBox(width: 12),

                        // 文本输入框
                        Expanded(
                          child: TextField(
                            controller: _controller,
                            decoration: InputDecoration(
                              hintText: l10n.chat_type_message_hint,
                              border: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(24),
                              ),
                              contentPadding: const EdgeInsets.symmetric(
                                horizontal: 20,
                                vertical: 12,
                              ),
                              suffixIcon: IconButton(
                                onPressed: () {
                                  _sendMessage();
                                },
                                icon: const Icon(Icons.send),
                                style: IconButton.styleFrom(
                                  backgroundColor: Theme.of(context).colorScheme.primary,
                                  foregroundColor: Theme.of(context).colorScheme.onPrimary,
                                ),
                              ),
                            ),
                            maxLines: 3,
                            minLines: 1,
                            textCapitalization: TextCapitalization.sentences,
                            onSubmitted: (_) => _sendMessage(),
                          ),
                        ),

                        // 语音输入按钮
                        const SizedBox(width: 12),
                        IconButton.filled(
                          onPressed: () {
                            _startVoiceInput();
                          },
                          icon: const Icon(Icons.mic),
                          tooltip: 'Voice Input',
                          style: IconButton.styleFrom(
                            backgroundColor: Theme.of(context).colorScheme.primaryContainer,
                            foregroundColor: Theme.of(context).colorScheme.onPrimaryContainer,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  /// 构建消息气泡
  Widget _buildMessageBubble(ChatMessage message) {
    final isUser = message.isUser;
    final screenWidth = MediaQuery.of(context).size.width;
    final isMobile = screenWidth < 600;

    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Row(
        mainAxisAlignment: isUser ? MainAxisAlignment.end : MainAxisAlignment.start,
        children: [
          if (!isUser) ...[
            CircleAvatar(
              backgroundColor: Theme.of(context).colorScheme.primaryContainer,
              child: Icon(
                Icons.psychology,
                color: Theme.of(context).colorScheme.onPrimaryContainer,
              ),
            ),
            const SizedBox(width: 12),
          ],
          Flexible(
            child: Container(
              constraints: BoxConstraints(
                maxWidth: isMobile ? screenWidth * 0.8 : screenWidth * 0.6,
              ),
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: isUser
                    ? Theme.of(context).colorScheme.primaryContainer
                    : Theme.of(context).colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(16),
                border: isUser
                    ? null
                    : Border.all(
                        color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.2),
                      ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    message.content,
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: isUser
                              ? Theme.of(context).colorScheme.onPrimaryContainer
                              : Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                  ),
                  const SizedBox(height: 8),
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        _formatTime(message.timestamp),
                        style: Theme.of(context).textTheme.bodySmall?.copyWith(
                              color: Theme.of(context).colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
                            ),
                      ),
                      if (!isUser) ...[
                        const SizedBox(width: 8),
                        // 复制按钮
                        IconButton(
                          onPressed: () {
                            _copyMessage(message.content);
                          },
                          icon: const Icon(Icons.copy, size: 16),
                          visualDensity: VisualDensity.compact,
                          style: IconButton.styleFrom(
                            foregroundColor: Theme.of(context).colorScheme.onSurfaceVariant,
                          ),
                        ),
                        // 重新生成按钮
                        IconButton(
                          onPressed: () {
                            _regenerateResponse();
                          },
                          icon: const Icon(Icons.refresh, size: 16),
                          visualDensity: VisualDensity.compact,
                          style: IconButton.styleFrom(
                            foregroundColor: Theme.of(context).colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ],
                  ),
                ],
              ),
            ),
          ),
          if (isUser) ...[
            const SizedBox(width: 12),
            CircleAvatar(
              backgroundColor: Theme.of(context).colorScheme.secondaryContainer,
              child: Icon(
                Icons.person,
                color: Theme.of(context).colorScheme.onSecondaryContainer,
              ),
            ),
          ],
        ],
      ),
    );
  }

  /// 发送消息
  void _sendMessage() {
    final text = _controller.text.trim();
    if (text.isEmpty) return;

    setState(() {
      _messages.add(ChatMessage(
        content: text,
        isUser: true,
        timestamp: DateTime.now(),
      ));
    });

    _controller.clear();
    _scrollToBottom();

    // 模拟AI响应
    Future.delayed(const Duration(seconds: 1), () {
      if (mounted) {
        setState(() {
          _messages.add(ChatMessage(
            content: _generateMockResponse(text),
            isUser: false,
            timestamp: DateTime.now(),
          ));
        });
        _scrollToBottom();
      }
    });
  }

  /// 生成模拟响应
  String _generateMockResponse(String userMessage) {
    // 简单的模拟响应逻辑
    if (userMessage.toLowerCase().contains('hello') || userMessage.toLowerCase().contains('hi')) {
      return '你好！很高兴见到你。今天有什么我可以帮助你的吗？';
    } else if (userMessage.toLowerCase().contains('help')) {
      return '我可以帮助你：\n\n• 回答问题和提供信息\n• 生成文本内容\n• 代码编写和调试\n• 翻译和语言学习\n• 创意写作和头脑风暴\n• 数据分析和解释\n\n还有什么特定的帮助需要吗？';
    } else if (userMessage.toLowerCase().contains('code')) {
      return '我可以帮助你编写各种编程语言的代码，包括Python、JavaScript、Java、C++等。请告诉我你需要什么类型的代码帮助？';
    } else {
      return '这是一个很好的问题。基于你的询问，我建议...\n\n\n这里有一些相关的信息和建议：\n\n1. 首先考虑这个问题的背景\n2. 分析可能的解决方案\n3. 评估每种方案的优缺点\n\n需要我详细解释某个方面吗？';
    }
  }

  /// 滚动到底部
  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 300),
          curve: Curves.easeOut,
        );
      }
    });
  }

  /// 格式化时间
  String _formatTime(DateTime time) {
    final now = DateTime.now();
    final difference = now.difference(time);

    if (difference.inMinutes < 1) {
      return 'Just now';
    } else if (difference.inHours < 1) {
      return '${difference.inMinutes} min ago';
    } else if (difference.inDays < 1) {
      return '${difference.inHours} h ago';
    } else {
      return '${difference.inDays} d ago';
    }
  }

  /// 复制消息
  void _copyMessage(String content) {
    // TODO: 实现复制功能
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Message copied to clipboard')),
    );
  }

  /// 重新生成响应
  void _regenerateResponse() {
    // TODO: 实现重新生成逻辑
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Regenerating response...')),
    );
  }

  /// 显示清除对话对话框
  void _showClearChatDialog(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.chat_clear_history),
        content: Text(l10n.chat_confirm_clear),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text(l10n.cancel),
          ),
          FilledButton(
            onPressed: () {
              setState(() {
                _messages.clear();
                _messages.add(ChatMessage(
                  content: l10n.welcome,
                  isUser: false,
                  timestamp: DateTime.now(),
                ));
              });
              Navigator.of(context).pop();
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(content: Text(l10n.action_completed)),
              );
            },
            child: Text(l10n.chat_clear_history),
          ),
        ],
      ),
    );
  }

  /// 显示设置对话框
  void _showSettingsDialog(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.assistant_settings),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.speed),
              title: const Text('Response Speed'),
              subtitle: const Text('Balanced'),
              trailing: const Icon(Icons.chevron_right),
              onTap: () {},
            ),
            ListTile(
              leading: const Icon(Icons.format_size),
              title: const Text('Response Length'),
              subtitle: const Text('Medium'),
              trailing: const Icon(Icons.chevron_right),
              onTap: () {},
            ),
            ListTile(
              leading: const Icon(Icons.language),
              title: Text(l10n.language),
              subtitle: const Text('Auto-detect'),
              trailing: const Icon(Icons.chevron_right),
              onTap: () {},
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text(l10n.close),
          ),
        ],
      ),
    );
  }

  /// 显示模式选择器
  void _showModeSelector(BuildContext context) {
    // TODO: 实现模式选择器
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Chat mode selector coming soon!')),
    );
  }

  /// 显示附件选项
  void _showAttachmentOptions(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    showModalBottomSheet(
      context: context,
      builder: (context) => Container(
        padding: const EdgeInsets.all(16),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              'Attach File',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 16),
            ListTile(
              leading: const Icon(Icons.image),
              title: const Text('Image'),
              onTap: () {
                Navigator.of(context).pop();
                // TODO: 实现图片选择
              },
            ),
            ListTile(
              leading: const Icon(Icons.description),
              title: const Text('Document'),
              onTap: () {
                Navigator.of(context).pop();
                // TODO: 实现文档选择
              },
            ),
            ListTile(
              leading: const Icon(Icons.code),
              title: const Text('Code'),
              onTap: () {
                Navigator.of(context).pop();
                // TODO: 实现代码输入
              },
            ),
          ],
        ),
      ),
    );
  }

  /// 开始语音输入
  void _startVoiceInput() {
    // TODO: 实现语音输入
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Voice input coming soon!')),
    );
  }
}

/// 聊天消息模型
class ChatMessage {
  final String content;
  final bool isUser;
  final DateTime timestamp;

  ChatMessage({
    required this.content,
    required this.isUser,
    required this.timestamp,
  });
}