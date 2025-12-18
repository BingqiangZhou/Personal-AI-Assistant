// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'chat_message_model.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

ChatMessageModel _$ChatMessageModelFromJson(Map<String, dynamic> json) =>
    ChatMessageModel(
      id: json['id'] as String,
      sessionId: json['sessionId'] as String,
      content: json['content'] as String,
      type: $enumDecode(_$MessageTypeEnumMap, json['type']),
      role: $enumDecode(_$MessageRoleEnumMap, json['role']),
      attachmentIds: (json['attachmentIds'] as List<dynamic>?)
          ?.map((e) => e as String)
          .toList(),
      metadata: json['metadata'] as Map<String, dynamic>?,
      createdAt: DateTime.parse(json['createdAt'] as String),
      updatedAt: DateTime.parse(json['updatedAt'] as String),
      isEdited: json['isEdited'] as bool? ?? false,
      tokenCount: (json['tokenCount'] as num?)?.toInt(),
      feedback: json['feedback'] as Map<String, dynamic>?,
    );

Map<String, dynamic> _$ChatMessageModelToJson(ChatMessageModel instance) =>
    <String, dynamic>{
      'id': instance.id,
      'sessionId': instance.sessionId,
      'content': instance.content,
      'type': _$MessageTypeEnumMap[instance.type]!,
      'role': _$MessageRoleEnumMap[instance.role]!,
      'attachmentIds': instance.attachmentIds,
      'metadata': instance.metadata,
      'createdAt': instance.createdAt.toIso8601String(),
      'updatedAt': instance.updatedAt.toIso8601String(),
      'isEdited': instance.isEdited,
      'tokenCount': instance.tokenCount,
      'feedback': instance.feedback,
    };

const _$MessageTypeEnumMap = {
  MessageType.text: 'text',
  MessageType.image: 'image',
  MessageType.file: 'file',
  MessageType.code: 'code',
  MessageType.markdown: 'markdown',
};

const _$MessageRoleEnumMap = {
  MessageRole.user: 'user',
  MessageRole.assistant: 'assistant',
  MessageRole.system: 'system',
};

SendMessageRequest _$SendMessageRequestFromJson(Map<String, dynamic> json) =>
    SendMessageRequest(
      content: json['content'] as String,
      type:
          $enumDecodeNullable(_$MessageTypeEnumMap, json['type']) ??
          MessageType.text,
      attachmentIds: (json['attachmentIds'] as List<dynamic>?)
          ?.map((e) => e as String)
          .toList(),
      metadata: json['metadata'] as Map<String, dynamic>?,
      streamResponse: json['streamResponse'] as bool? ?? false,
    );

Map<String, dynamic> _$SendMessageRequestToJson(SendMessageRequest instance) =>
    <String, dynamic>{
      'content': instance.content,
      'type': _$MessageTypeEnumMap[instance.type]!,
      'attachmentIds': instance.attachmentIds,
      'metadata': instance.metadata,
      'streamResponse': instance.streamResponse,
    };

StreamMessageResponse _$StreamMessageResponseFromJson(
  Map<String, dynamic> json,
) => StreamMessageResponse(
  id: json['id'] as String,
  sessionId: json['sessionId'] as String,
  content: json['content'] as String,
  isComplete: json['isComplete'] as bool,
  error: json['error'] as String?,
  metadata: json['metadata'] as Map<String, dynamic>?,
);

Map<String, dynamic> _$StreamMessageResponseToJson(
  StreamMessageResponse instance,
) => <String, dynamic>{
  'id': instance.id,
  'sessionId': instance.sessionId,
  'content': instance.content,
  'isComplete': instance.isComplete,
  'error': instance.error,
  'metadata': instance.metadata,
};

MessageFeedback _$MessageFeedbackFromJson(Map<String, dynamic> json) =>
    MessageFeedback(
      messageId: json['messageId'] as String,
      type: $enumDecode(_$FeedbackTypeEnumMap, json['type']),
      comment: json['comment'] as String?,
      rating: (json['rating'] as num).toInt(),
      createdAt: DateTime.parse(json['createdAt'] as String),
    );

Map<String, dynamic> _$MessageFeedbackToJson(MessageFeedback instance) =>
    <String, dynamic>{
      'messageId': instance.messageId,
      'type': _$FeedbackTypeEnumMap[instance.type]!,
      'comment': instance.comment,
      'rating': instance.rating,
      'createdAt': instance.createdAt.toIso8601String(),
    };

const _$FeedbackTypeEnumMap = {
  FeedbackType.thumbsUp: 'thumbs_up',
  FeedbackType.thumbsDown: 'thumbs_down',
  FeedbackType.star: 'star',
  FeedbackType.comment: 'comment',
};
