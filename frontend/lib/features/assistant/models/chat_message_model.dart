import 'package:json_annotation/json_annotation.dart';

part 'chat_message_model.g.dart';

@JsonSerializable()
class ChatMessageModel {
  final String id;
  final String sessionId;
  final String content;
  final MessageType type;
  final MessageRole role;
  final List<String>? attachmentIds;
  final Map<String, dynamic>? metadata;
  final DateTime createdAt;
  final DateTime updatedAt;
  final bool isEdited;
  final int? tokenCount;
  final Map<String, dynamic>? feedback;

  const ChatMessageModel({
    required this.id,
    required this.sessionId,
    required this.content,
    required this.type,
    required this.role,
    this.attachmentIds,
    this.metadata,
    required this.createdAt,
    required this.updatedAt,
    this.isEdited = false,
    this.tokenCount,
    this.feedback,
  });

  factory ChatMessageModel.fromJson(Map<String, dynamic> json) =>
      _$ChatMessageModelFromJson(json);

  Map<String, dynamic> toJson() => _$ChatMessageModelToJson(this);

  ChatMessageModel copyWith({
    String? id,
    String? sessionId,
    String? content,
    MessageType? type,
    MessageRole? role,
    List<String>? attachmentIds,
    Map<String, dynamic>? metadata,
    DateTime? createdAt,
    DateTime? updatedAt,
    bool? isEdited,
    int? tokenCount,
    Map<String, dynamic>? feedback,
  }) {
    return ChatMessageModel(
      id: id ?? this.id,
      sessionId: sessionId ?? this.sessionId,
      content: content ?? this.content,
      type: type ?? this.type,
      role: role ?? this.role,
      attachmentIds: attachmentIds ?? this.attachmentIds,
      metadata: metadata ?? this.metadata,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      isEdited: isEdited ?? this.isEdited,
      tokenCount: tokenCount ?? this.tokenCount,
      feedback: feedback ?? this.feedback,
    );
  }

  bool get isUser => role == MessageRole.user;
  bool get isAssistant => role == MessageRole.assistant;
  bool get isSystem => role == MessageRole.system;
}

enum MessageType {
  @JsonValue('text')
  text,
  @JsonValue('image')
  image,
  @JsonValue('file')
  file,
  @JsonValue('code')
  code,
  @JsonValue('markdown')
  markdown,
}

enum MessageRole {
  @JsonValue('user')
  user,
  @JsonValue('assistant')
  assistant,
  @JsonValue('system')
  system,
}

@JsonSerializable()
class SendMessageRequest {
  final String content;
  final MessageType type;
  final List<String>? attachmentIds;
  final Map<String, dynamic>? metadata;
  final bool streamResponse;

  const SendMessageRequest({
    required this.content,
    this.type = MessageType.text,
    this.attachmentIds,
    this.metadata,
    this.streamResponse = false,
  });

  factory SendMessageRequest.fromJson(Map<String, dynamic> json) =>
      _$SendMessageRequestFromJson(json);

  Map<String, dynamic> toJson() => _$SendMessageRequestToJson(this);
}

@JsonSerializable()
class StreamMessageResponse {
  final String id;
  final String sessionId;
  final String content;
  final bool isComplete;
  final String? error;
  final Map<String, dynamic>? metadata;

  const StreamMessageResponse({
    required this.id,
    required this.sessionId,
    required this.content,
    required this.isComplete,
    this.error,
    this.metadata,
  });

  factory StreamMessageResponse.fromJson(Map<String, dynamic> json) =>
      _$StreamMessageResponseFromJson(json);

  Map<String, dynamic> toJson() => _$StreamMessageResponseToJson(this);
}

@JsonSerializable()
class MessageFeedback {
  final String messageId;
  final FeedbackType type;
  final String? comment;
  final int rating;
  final DateTime createdAt;

  const MessageFeedback({
    required this.messageId,
    required this.type,
    this.comment,
    required this.rating,
    required this.createdAt,
  });

  factory MessageFeedback.fromJson(Map<String, dynamic> json) =>
      _$MessageFeedbackFromJson(json);

  Map<String, dynamic> toJson() => _$MessageFeedbackToJson(this);
}

enum FeedbackType {
  @JsonValue('thumbs_up')
  thumbsUp,
  @JsonValue('thumbs_down')
  thumbsDown,
  @JsonValue('star')
  star,
  @JsonValue('comment')
  comment,
}