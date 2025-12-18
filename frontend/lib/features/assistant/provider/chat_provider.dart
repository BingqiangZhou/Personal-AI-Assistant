import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:meta/meta.dart';

import '../../../core/providers/core_providers.dart';
import '../models/chat_message_model.dart';
import '../models/chat_session_model.dart';

// Chat Sessions State
@immutable
class ChatSessionsState {
  final bool isLoading;
  final List<ChatSessionModel> sessions;
  final String? error;

  const ChatSessionsState({
    this.isLoading = false,
    this.sessions = const [],
    this.error,
  });

  ChatSessionsState copyWith({
    bool? isLoading,
    List<ChatSessionModel>? sessions,
    String? error,
  }) {
    return ChatSessionsState(
      isLoading: isLoading ?? this.isLoading,
      sessions: sessions ?? this.sessions,
      error: error ?? this.error,
    );
  }
}

// Chat Session State
@immutable
class ChatSessionState {
  final bool isLoading;
  final ChatSessionModel? session;
  final List<ChatMessageModel> messages;
  final bool isStreamingResponse;
  final String? error;
  final bool hasMoreMessages;

  const ChatSessionState({
    this.isLoading = false,
    this.session,
    this.messages = const [],
    this.isStreamingResponse = false,
    this.error,
    this.hasMoreMessages = true,
  });

  ChatSessionState copyWith({
    bool? isLoading,
    ChatSessionModel? session,
    List<ChatMessageModel>? messages,
    bool? isStreamingResponse,
    String? error,
    bool? hasMoreMessages,
  }) {
    return ChatSessionState(
      isLoading: isLoading ?? this.isLoading,
      session: session ?? this.session,
      messages: messages ?? this.messages,
      isStreamingResponse: isStreamingResponse ?? this.isStreamingResponse,
      error: error ?? this.error,
      hasMoreMessages: hasMoreMessages ?? this.hasMoreMessages,
    );
  }
}

// Chat Sessions Provider
final chatSessionsProvider = NotifierProvider<ChatSessionsNotifier, ChatSessionsState>(ChatSessionsNotifier.new);

class ChatSessionsNotifier extends Notifier<ChatSessionsState> {
  @override
  ChatSessionsState build() {
    _loadSessions();
    return const ChatSessionsState();
  }

  // Load all chat sessions
  Future<void> _loadSessions() async {
    try {
      state = state.copyWith(isLoading: true, error: null);

      final apiService = ref.read(apiServiceProvider);
      final sessions = await apiService.getChatSessions();

      // Sort sessions by last message date
      sessions.sort((a, b) => b.lastMessageAt?.compareTo(a.lastMessageAt ?? DateTime.now()) ?? 0);

      state = state.copyWith(
        isLoading: false,
        sessions: sessions,
      );
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
    }
  }

  // Create new chat session
  Future<ChatSessionModel> createSession({
    required String title,
    String? description,
    List<String>? knowledgeBaseIds,
    Map<String, dynamic>? settings,
  }) async {
    try {
      state = state.copyWith(isLoading: true);

      final apiService = ref.read(apiServiceProvider);
      final newSession = await apiService.createChatSession({
        'title': title,
        'description': description,
        'knowledge_base_ids': knowledgeBaseIds ?? [],
        'settings': settings ?? {},
      });

      final updatedSessions = [newSession, ...state.sessions];
      updatedSessions.sort((a, b) => b.lastMessageAt?.compareTo(a.lastMessageAt ?? DateTime.now()) ?? 0);

      state = state.copyWith(
        isLoading: false,
        sessions: updatedSessions,
      );

      return newSession;
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
      rethrow;
    }
  }

  // Delete chat session
  Future<void> deleteSession(String sessionId) async {
    try {
      final apiService = ref.read(apiServiceProvider);
      await apiService.deleteChatSession(sessionId);

      final updatedSessions = state.sessions.where((session) => session.id != sessionId).toList();
      state = state.copyWith(sessions: updatedSessions);
    } catch (e) {
      state = state.copyWith(error: e.toString());
      rethrow;
    }
  }

  // Update chat session
  Future<void> updateSession({
    required String sessionId,
    String? title,
    String? description,
    List<String>? knowledgeBaseIds,
    Map<String, dynamic>? settings,
  }) async {
    try {
      final apiService = ref.read(apiServiceProvider);
      final updatedSession = await apiService.updateChatSession(sessionId, {
        'title': title,
        'description': description,
        'knowledge_base_ids': knowledgeBaseIds,
        'settings': settings,
      });

      final updatedSessions = state.sessions.map((session) {
        return session.id == sessionId ? updatedSession : session;
      }).toList();

      state = state.copyWith(sessions: updatedSessions);
    } catch (e) {
      state = state.copyWith(error: e.toString());
      rethrow;
    }
  }

  // Refresh sessions
  Future<void> refreshSessions() {
    return _loadSessions();
  }

  // Clear error
  void clearError() {
    state = state.copyWith(error: null);
  }
}

// Individual Chat Session Provider
final chatSessionProvider = NotifierProvider.family<ChatSessionNotifier, ChatSessionState, String>(ChatSessionNotifier.new);

class ChatSessionNotifier extends FamilyNotifier<ChatSessionState, String> {
  @override
  ChatSessionState build(String arg) {
    _loadSession();
    return const ChatSessionState();
  }

  // Load chat session and messages
  Future<void> _loadSession() async {
    try {
      state = state.copyWith(isLoading: true, error: null);

      final apiService = ref.read(apiServiceProvider);

      // Load session details
      final session = await apiService.getChatSession(arg);

      // Load messages
      final messages = await apiService.getChatMessages(arg);

      state = state.copyWith(
        isLoading: false,
        session: session,
        messages: messages,
      );
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
    }
  }

  // Send message
  Future<void> sendMessage({
    required String content,
    MessageType type = MessageType.text,
    List<String>? attachmentIds,
    Map<String, dynamic>? metadata,
    bool streamResponse = true,
  }) async {
    try {
      // Create user message immediately
      final userMessage = ChatMessageModel(
        id: 'temp_${DateTime.now().millisecondsSinceEpoch}',
        sessionId: arg,
        content: content,
        type: type,
        role: MessageRole.user,
        attachmentIds: attachmentIds,
        metadata: metadata,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final updatedMessages = [...state.messages, userMessage];
      state = state.copyWith(messages: updatedMessages);

      if (streamResponse) {
        state = state.copyWith(isStreamingResponse: true);

        // TODO: Implement streaming response
        // For now, send a regular message
        final apiService = ref.read(apiServiceProvider);
        final assistantMessage = await apiService.sendMessage(arg, {
          'content': content,
          'type': type.name,
          'attachment_ids': attachmentIds ?? [],
          'metadata': metadata ?? {},
          'stream_response': false,
        });

        final finalMessages = [...updatedMessages, assistantMessage];
        state = state.copyWith(
          messages: finalMessages,
          isStreamingResponse: false,
        );
      } else {
        final apiService = ref.read(apiServiceProvider);
        final assistantMessage = await apiService.sendMessage(arg, {
          'content': content,
          'type': type.name,
          'attachment_ids': attachmentIds ?? [],
          'metadata': metadata ?? {},
          'stream_response': false,
        });

        final finalMessages = [...updatedMessages, assistantMessage];
        state = state.copyWith(messages: finalMessages);
      }
    } catch (e) {
      state = state.copyWith(
        error: e.toString(),
        isStreamingResponse: false,
      );
      rethrow;
    }
  }

  // Load more messages (pagination)
  Future<void> loadMoreMessages() async {
    if (!state.hasMoreMessages || state.isLoading) return;

    try {
      state = state.copyWith(isLoading: true);

      final apiService = ref.read(apiServiceProvider);
      final moreMessages = await apiService.getChatMessages(
        arg,
        limit: 20,
        offset: state.messages.length,
      );

      if (moreMessages.isEmpty) {
        state = state.copyWith(
          hasMoreMessages: false,
          isLoading: false,
        );
      } else {
        final allMessages = [...state.messages, ...moreMessages];
        state = state.copyWith(
          messages: allMessages,
          isLoading: false,
        );
      }
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
    }
  }

  // Delete message
  Future<void> deleteMessage(String messageId) async {
    try {
      // TODO: Implement delete message API
      final updatedMessages = state.messages.where((message) => message.id != messageId).toList();
      state = state.copyWith(messages: updatedMessages);
    } catch (e) {
      state = state.copyWith(error: e.toString());
      rethrow;
    }
  }

  // Rate message
  Future<void> rateMessage({
    required String messageId,
    required int rating,
    FeedbackType? feedbackType,
    String? comment,
  }) async {
    try {
      // TODO: Implement message rating API

      // Update local state
      final updatedMessages = state.messages.map((message) {
        if (message.id == messageId) {
          return message.copyWith(
            feedback: {
              'rating': rating,
              'type': feedbackType?.name,
              'comment': comment,
              'created_at': DateTime.now().toIso8601String(),
            },
          );
        }
        return message;
      }).toList();

      state = state.copyWith(messages: updatedMessages);
    } catch (e) {
      state = state.copyWith(error: e.toString());
      rethrow;
    }
  }

  // Refresh session
  Future<void> refreshSession() {
    return _loadSession();
  }

  // Clear error
  void clearError() {
    state = state.copyWith(error: null);
  }
}

// Current active chat session ID provider
final activeChatSessionIdProvider = NotifierProvider<ActiveChatSessionIdNotifier, String?>(ActiveChatSessionIdNotifier.new);

class ActiveChatSessionIdNotifier extends Notifier<String?> {
  @override
  String? build() {
    return null;
  }

  void setSessionId(String? sessionId) {
    state = sessionId;
  }
}

// Current active chat session provider
final activeChatSessionProvider = Provider<ChatSessionState?>((ref) {
  final sessionId = ref.watch(activeChatSessionIdProvider);
  if (sessionId == null) return null;
  return ref.watch(chatSessionProvider(sessionId));
});