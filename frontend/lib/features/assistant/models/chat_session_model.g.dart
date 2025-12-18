// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'chat_session_model.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

ChatSessionModel _$ChatSessionModelFromJson(Map<String, dynamic> json) =>
    ChatSessionModel(
      id: json['id'] as String,
      title: json['title'] as String,
      description: json['description'] as String?,
      userId: json['userId'] as String,
      knowledgeBaseIds: (json['knowledgeBaseIds'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      settings: json['settings'] as Map<String, dynamic>?,
      createdAt: DateTime.parse(json['createdAt'] as String),
      updatedAt: DateTime.parse(json['updatedAt'] as String),
      lastMessageAt: json['lastMessageAt'] == null
          ? null
          : DateTime.parse(json['lastMessageAt'] as String),
      messageCount: (json['messageCount'] as num).toInt(),
      isActive: json['isActive'] as bool,
      metadata: json['metadata'] as Map<String, dynamic>?,
    );

Map<String, dynamic> _$ChatSessionModelToJson(ChatSessionModel instance) =>
    <String, dynamic>{
      'id': instance.id,
      'title': instance.title,
      'description': instance.description,
      'userId': instance.userId,
      'knowledgeBaseIds': instance.knowledgeBaseIds,
      'settings': instance.settings,
      'createdAt': instance.createdAt.toIso8601String(),
      'updatedAt': instance.updatedAt.toIso8601String(),
      'lastMessageAt': instance.lastMessageAt?.toIso8601String(),
      'messageCount': instance.messageCount,
      'isActive': instance.isActive,
      'metadata': instance.metadata,
    };

CreateChatSessionRequest _$CreateChatSessionRequestFromJson(
  Map<String, dynamic> json,
) => CreateChatSessionRequest(
  title: json['title'] as String,
  description: json['description'] as String?,
  knowledgeBaseIds: (json['knowledgeBaseIds'] as List<dynamic>?)
      ?.map((e) => e as String)
      .toList(),
  settings: json['settings'] as Map<String, dynamic>?,
);

Map<String, dynamic> _$CreateChatSessionRequestToJson(
  CreateChatSessionRequest instance,
) => <String, dynamic>{
  'title': instance.title,
  'description': instance.description,
  'knowledgeBaseIds': instance.knowledgeBaseIds,
  'settings': instance.settings,
};

UpdateChatSessionRequest _$UpdateChatSessionRequestFromJson(
  Map<String, dynamic> json,
) => UpdateChatSessionRequest(
  title: json['title'] as String?,
  description: json['description'] as String?,
  knowledgeBaseIds: (json['knowledgeBaseIds'] as List<dynamic>?)
      ?.map((e) => e as String)
      .toList(),
  settings: json['settings'] as Map<String, dynamic>?,
  isActive: json['isActive'] as bool?,
);

Map<String, dynamic> _$UpdateChatSessionRequestToJson(
  UpdateChatSessionRequest instance,
) => <String, dynamic>{
  'title': instance.title,
  'description': instance.description,
  'knowledgeBaseIds': instance.knowledgeBaseIds,
  'settings': instance.settings,
  'isActive': instance.isActive,
};
