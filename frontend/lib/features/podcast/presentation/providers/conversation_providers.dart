import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../data/models/podcast_conversation_model.dart';
import 'podcast_providers.dart';

// Conversation state providers for each episode
final conversationStateProviders = <int, NotifierProvider<ConversationNotifier, ConversationState>>{};

/// Get or create a conversation state provider for a specific episode
NotifierProvider<ConversationNotifier, ConversationState> getConversationProvider(int episodeId) {
  return conversationStateProviders.putIfAbsent(
    episodeId,
    () => NotifierProvider<ConversationNotifier, ConversationState>(() => ConversationNotifier(episodeId)),
  );
}

/// Conversation state class
class ConversationState {
  final List<PodcastConversationMessage> messages;
  final bool isLoading;
  final bool isSending;
  final String? errorMessage;
  final int? currentSendingTurn;

  const ConversationState({
    this.messages = const [],
    this.isLoading = false,
    this.isSending = false,
    this.errorMessage,
    this.currentSendingTurn,
  });

  bool get hasError => errorMessage != null;
  bool get hasMessages => messages.isNotEmpty;
  bool get isEmpty => messages.isEmpty;
  bool get isReady => !isLoading && !isSending;

  /// Get user messages
  List<PodcastConversationMessage> get userMessages =>
      messages.where((m) => m.isUser).toList();

  /// Get assistant messages
  List<PodcastConversationMessage> get assistantMessages =>
      messages.where((m) => m.isAssistant).toList();

  ConversationState copyWith({
    List<PodcastConversationMessage>? messages,
    bool? isLoading,
    bool? isSending,
    String? errorMessage,
    int? currentSendingTurn,
  }) {
    return ConversationState(
      messages: messages ?? this.messages,
      isLoading: isLoading ?? this.isLoading,
      isSending: isSending ?? this.isSending,
      errorMessage: errorMessage ?? this.errorMessage,
      currentSendingTurn: currentSendingTurn ?? this.currentSendingTurn,
    );
  }
}

/// Notifier for managing conversation state
class ConversationNotifier extends Notifier<ConversationState> {
  final int episodeId;

  ConversationNotifier(this.episodeId);

  @override
  ConversationState build() {
    // Load conversation history when building
    _loadHistory();
    return const ConversationState(isLoading: true);
  }

  /// Load conversation history from backend
  Future<void> _loadHistory() async {
    try {
      final repository = ref.read(podcastRepositoryProvider);
      final response = await repository.getConversationHistory(episodeId: episodeId);

      state = ConversationState(
        messages: response.messages,
        isLoading: false,
      );
    } catch (e) {
      state = ConversationState(
        messages: const [],
        isLoading: false,
        errorMessage: e.toString(),
      );
    }
  }

  /// Refresh conversation history
  Future<void> refresh() async {
    state = state.copyWith(isLoading: true, errorMessage: null);
    await _loadHistory();
  }

  /// Send a message to AI
  Future<void> sendMessage(String message, {String? modelName}) async {
    // Optimistically add user message to state
    final userTurn = state.messages.length;
    final optimisticUserMessage = PodcastConversationMessage(
      id: -userTurn, // Temporary negative ID
      role: 'user',
      content: message,
      conversationTurn: userTurn,
      createdAt: DateTime.now().toIso8601String(),
    );

    state = state.copyWith(
      messages: [...state.messages, optimisticUserMessage],
      isSending: true,
      currentSendingTurn: userTurn,
      errorMessage: null,
    );

    try {
      final repository = ref.read(podcastRepositoryProvider);
      final response = await repository.sendConversationMessage(
        episodeId: episodeId,
        request: PodcastConversationSendRequest(
          message: message,
          modelName: modelName,
        ),
      );

      // Replace optimistic messages with actual response
      final updatedMessages = List<PodcastConversationMessage>.from(state.messages);
      // Remove optimistic user message (will be reloaded from server)
      updatedMessages.removeWhere((m) => m.id < 0);
      // Add both user and assistant messages from server
      updatedMessages.add(response.toMessage());

      state = ConversationState(
        messages: updatedMessages,
        isSending: false,
        currentSendingTurn: null,
      );
    } catch (e) {
      // Remove optimistic message on error
      final updatedMessages = List<PodcastConversationMessage>.from(state.messages);
      updatedMessages.removeWhere((m) => m.id < 0);

      state = ConversationState(
        messages: updatedMessages,
        isSending: false,
        currentSendingTurn: null,
        errorMessage: e.toString(),
      );
    }
  }

  /// Clear conversation history
  Future<void> clearHistory() async {
    state = state.copyWith(isLoading: true);

    try {
      final repository = ref.read(podcastRepositoryProvider);
      await repository.clearConversationHistory(episodeId: episodeId);

      state = const ConversationState(
        messages: [],
        isLoading: false,
      );
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        errorMessage: e.toString(),
      );
    }
  }

  /// Clear error
  void clearError() {
    if (state.hasError) {
      state = state.copyWith(errorMessage: null);
    }
  }

  /// Get last assistant message
  PodcastConversationMessage? get lastAssistantMessage {
    for (var i = state.messages.length - 1; i >= 0; i--) {
      if (state.messages[i].isAssistant) {
        return state.messages[i];
      }
    }
    return null;
  }

  /// Get conversation title (first user message)
  String get conversationTitle {
    final firstUserMessage = state.messages.isNotEmpty && state.messages.first.isUser
        ? state.messages.first.content
        : '对话';
    // Truncate if too long
    if (firstUserMessage.length > 30) {
      return '${firstUserMessage.substring(0, 30)}...';
    }
    return firstUserMessage;
  }
}
