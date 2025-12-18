import 'package:json_annotation/json_annotation.dart';

part 'chat_session_model.g.dart';

@JsonSerializable()
class ChatSessionModel {
  final String id;
  final String title;
  final String? description;
  final String userId;
  final List<String> knowledgeBaseIds;
  final Map<String, dynamic>? settings;
  final DateTime createdAt;
  final DateTime updatedAt;
  final DateTime? lastMessageAt;
  final int messageCount;
  final bool isActive;
  final Map<String, dynamic>? metadata;

  const ChatSessionModel({
    required this.id,
    required this.title,
    this.description,
    required this.userId,
    required this.knowledgeBaseIds,
    this.settings,
    required this.createdAt,
    required this.updatedAt,
    this.lastMessageAt,
    required this.messageCount,
    required this.isActive,
    this.metadata,
  });

  factory ChatSessionModel.fromJson(Map<String, dynamic> json) =>
      _$ChatSessionModelFromJson(json);

  Map<String, dynamic> toJson() => _$ChatSessionModelToJson(this);

  ChatSessionModel copyWith({
    String? id,
    String? title,
    String? description,
    String? userId,
    List<String>? knowledgeBaseIds,
    Map<String, dynamic>? settings,
    DateTime? createdAt,
    DateTime? updatedAt,
    DateTime? lastMessageAt,
    int? messageCount,
    bool? isActive,
    Map<String, dynamic>? metadata,
  }) {
    return ChatSessionModel(
      id: id ?? this.id,
      title: title ?? this.title,
      description: description ?? this.description,
      userId: userId ?? this.userId,
      knowledgeBaseIds: knowledgeBaseIds ?? this.knowledgeBaseIds,
      settings: settings ?? this.settings,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      lastMessageAt: lastMessageAt ?? this.lastMessageAt,
      messageCount: messageCount ?? this.messageCount,
      isActive: isActive ?? this.isActive,
      metadata: metadata ?? this.metadata,
    );
  }

  String get formattedLastMessageAt {
    if (lastMessageAt == null) return 'No messages';

    final now = DateTime.now();
    final difference = now.difference(lastMessageAt!);

    if (difference.inDays > 0) {
      return '${difference.inDays}d ago';
    } else if (difference.inHours > 0) {
      return '${difference.inHours}h ago';
    } else if (difference.inMinutes > 0) {
      return '${difference.inMinutes}m ago';
    } else {
      return 'Just now';
    }
  }
}

@JsonSerializable()
class CreateChatSessionRequest {
  final String title;
  final String? description;
  final List<String>? knowledgeBaseIds;
  final Map<String, dynamic>? settings;

  const CreateChatSessionRequest({
    required this.title,
    this.description,
    this.knowledgeBaseIds,
    this.settings,
  });

  factory CreateChatSessionRequest.fromJson(Map<String, dynamic> json) =>
      _$CreateChatSessionRequestFromJson(json);

  Map<String, dynamic> toJson() => _$CreateChatSessionRequestToJson(this);
}

@JsonSerializable()
class UpdateChatSessionRequest {
  final String? title;
  final String? description;
  final List<String>? knowledgeBaseIds;
  final Map<String, dynamic>? settings;
  final bool? isActive;

  const UpdateChatSessionRequest({
    this.title,
    this.description,
    this.knowledgeBaseIds,
    this.settings,
    this.isActive,
  });

  factory UpdateChatSessionRequest.fromJson(Map<String, dynamic> json) =>
      _$UpdateChatSessionRequestFromJson(json);

  Map<String, dynamic> toJson() => _$UpdateChatSessionRequestToJson(this);
}