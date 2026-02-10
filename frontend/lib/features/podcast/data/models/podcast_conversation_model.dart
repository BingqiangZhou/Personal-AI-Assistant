import 'package:equatable/equatable.dart';
import 'package:json_annotation/json_annotation.dart';

part 'podcast_conversation_model.g.dart';

/// 对话消息角色
enum ConversationRole {
  @JsonValue('user')
  user,
  @JsonValue('assistant')
  assistant,
}

/// 对话会话模型
@JsonSerializable()
class ConversationSession extends Equatable {
  final int id;
  @JsonKey(name: 'episode_id')
  final int episodeId;
  final String title;
  @JsonKey(name: 'message_count')
  final int messageCount;
  @JsonKey(name: 'created_at')
  final String createdAt;
  @JsonKey(name: 'updated_at')
  final String? updatedAt;

  const ConversationSession({
    required this.id,
    required this.episodeId,
    required this.title,
    this.messageCount = 0,
    required this.createdAt,
    this.updatedAt,
  });

  factory ConversationSession.fromJson(Map<String, dynamic> json) =>
      _$ConversationSessionFromJson(json);

  Map<String, dynamic> toJson() => _$ConversationSessionToJson(this);

  @override
  List<Object?> get props => [
        id,
        episodeId,
        title,
        messageCount,
        createdAt,
        updatedAt,
      ];
}

/// 对话会话列表响应
@JsonSerializable()
class ConversationSessionListResponse extends Equatable {
  final List<ConversationSession> sessions;
  final int total;

  const ConversationSessionListResponse({
    required this.sessions,
    required this.total,
  });

  factory ConversationSessionListResponse.fromJson(Map<String, dynamic> json) =>
      _$ConversationSessionListResponseFromJson(json);

  Map<String, dynamic> toJson() => _$ConversationSessionListResponseToJson(this);

  @override
  List<Object?> get props => [sessions, total];
}

/// 对话消息模型
@JsonSerializable()
class PodcastConversationMessage extends Equatable {
  final int id;
  final String role; // 'user' or 'assistant'
  final String content;
  @JsonKey(name: 'conversation_turn')
  final int conversationTurn;
  @JsonKey(name: 'created_at')
  final String createdAt;
  @JsonKey(name: 'parent_message_id')
  final int? parentMessageId;

  const PodcastConversationMessage({
    required this.id,
    required this.role,
    required this.content,
    required this.conversationTurn,
    required this.createdAt,
    this.parentMessageId,
  });

  factory PodcastConversationMessage.fromJson(Map<String, dynamic> json) =>
      _$PodcastConversationMessageFromJson(json);

  Map<String, dynamic> toJson() => _$PodcastConversationMessageToJson(this);

  /// 获取角色枚举
  ConversationRole get conversationRole {
    switch (role.toLowerCase()) {
      case 'user':
        return ConversationRole.user;
      case 'assistant':
        return ConversationRole.assistant;
      default:
        return ConversationRole.user;
    }
  }

  /// 是否为用户消息
  bool get isUser => conversationRole == ConversationRole.user;

  /// 是否为AI助手消息
  bool get isAssistant => conversationRole == ConversationRole.assistant;

  @override
  List<Object?> get props => [
        id,
        role,
        content,
        conversationTurn,
        createdAt,
        parentMessageId,
      ];
}

/// 发送对话消息请求
@JsonSerializable()
class PodcastConversationSendRequest extends Equatable {
  final String message;
  @JsonKey(name: 'model_name')
  final String? modelName;
  @JsonKey(name: 'session_id')
  final int? sessionId;

  const PodcastConversationSendRequest({
    required this.message,
    this.modelName,
    this.sessionId,
  });

  factory PodcastConversationSendRequest.fromJson(Map<String, dynamic> json) =>
      _$PodcastConversationSendRequestFromJson(json);

  Map<String, dynamic> toJson() => _$PodcastConversationSendRequestToJson(this);

  @override
  List<Object?> get props => [message, modelName, sessionId];
}

/// 发送对话消息响应
@JsonSerializable()
class PodcastConversationSendResponse extends Equatable {
  final int id;
  final String role;
  final String content;
  @JsonKey(name: 'conversation_turn')
  final int conversationTurn;
  @JsonKey(name: 'processing_time')
  final double? processingTime;
  @JsonKey(name: 'created_at')
  final String createdAt;

  const PodcastConversationSendResponse({
    required this.id,
    required this.role,
    required this.content,
    required this.conversationTurn,
    this.processingTime,
    required this.createdAt,
  });

  factory PodcastConversationSendResponse.fromJson(Map<String, dynamic> json) =>
      _$PodcastConversationSendResponseFromJson(json);

  Map<String, dynamic> toJson() => _$PodcastConversationSendResponseToJson(this);

  /// 转换为消息模型
  PodcastConversationMessage toMessage() {
    return PodcastConversationMessage(
      id: id,
      role: role,
      content: content,
      conversationTurn: conversationTurn,
      createdAt: createdAt,
      parentMessageId: null,
    );
  }

  @override
  List<Object?> get props => [
        id,
        role,
        content,
        conversationTurn,
        processingTime,
        createdAt,
      ];
}

/// 对话历史响应
@JsonSerializable()
class PodcastConversationHistoryResponse extends Equatable {
  @JsonKey(name: 'episode_id')
  final int episodeId;
  @JsonKey(name: 'session_id')
  final int? sessionId;
  final List<PodcastConversationMessage> messages;
  final int total;

  const PodcastConversationHistoryResponse({
    required this.episodeId,
    this.sessionId,
    required this.messages,
    required this.total,
  });

  factory PodcastConversationHistoryResponse.fromJson(Map<String, dynamic> json) =>
      _$PodcastConversationHistoryResponseFromJson(json);

  Map<String, dynamic> toJson() => _$PodcastConversationHistoryResponseToJson(this);

  @override
  List<Object?> get props => [episodeId, sessionId, messages, total];
}

/// 清除对话历史响应
@JsonSerializable()
class PodcastConversationClearResponse extends Equatable {
  @JsonKey(name: 'episode_id')
  final int episodeId;
  @JsonKey(name: 'session_id')
  final int? sessionId;
  @JsonKey(name: 'deleted_count')
  final int deletedCount;

  const PodcastConversationClearResponse({
    required this.episodeId,
    this.sessionId,
    required this.deletedCount,
  });

  factory PodcastConversationClearResponse.fromJson(Map<String, dynamic> json) =>
      _$PodcastConversationClearResponseFromJson(json);

  Map<String, dynamic> toJson() => _$PodcastConversationClearResponseToJson(this);

  @override
  List<Object?> get props => [episodeId, sessionId, deletedCount];
}
