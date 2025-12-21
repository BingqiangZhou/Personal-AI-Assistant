import 'package:equatable/equatable.dart';
import 'package:json_annotation/json_annotation.dart';

part 'knowledge_model.g.dart';

@JsonSerializable()
class KnowledgeBaseModel extends Equatable {
  final int id;
  @JsonKey(name: 'user_id')
  final int userId;
  final String name;
  final String? description;
  @JsonKey(name: 'is_public', defaultValue: false)
  final bool isPublic;
  @JsonKey(name: 'is_default', defaultValue: false)
  final bool isDefault;
  final Map<String, dynamic>? settings;
  @JsonKey(name: 'document_count', defaultValue: 0)
  final int documentCount;
  @JsonKey(name: 'created_at')
  final DateTime createdAt;
  @JsonKey(name: 'updated_at')
  final DateTime? updatedAt;

  const KnowledgeBaseModel({
    required this.id,
    required this.userId,
    required this.name,
    this.description,
    this.isPublic = false,
    this.isDefault = false,
    this.settings,
    this.documentCount = 0,
    required this.createdAt,
    this.updatedAt,
  });

  factory KnowledgeBaseModel.fromJson(Map<String, dynamic> json) =>
      _$KnowledgeBaseModelFromJson(json);

  Map<String, dynamic> toJson() => _$KnowledgeBaseModelToJson(this);

  KnowledgeBaseModel copyWith({
    int? id,
    int? userId,
    String? name,
    String? description,
    bool? isPublic,
    bool? isDefault,
    Map<String, dynamic>? settings,
    int? documentCount,
    DateTime? createdAt,
    DateTime? updatedAt,
  }) {
    return KnowledgeBaseModel(
      id: id ?? this.id,
      userId: userId ?? this.userId,
      name: name ?? this.name,
      description: description ?? this.description,
      isPublic: isPublic ?? this.isPublic,
      isDefault: isDefault ?? this.isDefault,
      settings: settings ?? this.settings,
      documentCount: documentCount ?? this.documentCount,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
    );
  }

  @override
  List<Object?> get props => [
        id,
        userId,
        name,
        description,
        isPublic,
        isDefault,
        settings,
        documentCount,
        createdAt,
        updatedAt,
      ];
}

@JsonSerializable()
class DocumentModel extends Equatable {
  final int id;
  @JsonKey(name: 'knowledge_base_id')
  final int knowledgeBaseId;
  final String title;
  final String? content;
  @JsonKey(name: 'content_type')
  final String contentType;
  final Map<String, dynamic>? metadata;
  final List<String>? tags;
  @JsonKey(name: 'file_path')
  final String? filePath;
  @JsonKey(name: 'file_size')
  final int? fileSize;
  @JsonKey(name: 'indexed_at')
  final DateTime? indexedAt;
  @JsonKey(name: 'created_at')
  final DateTime createdAt;
  @JsonKey(name: 'updated_at')
  final DateTime? updatedAt;

  const DocumentModel({
    required this.id,
    required this.knowledgeBaseId,
    required this.title,
    this.content,
    required this.contentType,
    this.metadata,
    this.tags,
    this.filePath,
    this.fileSize,
    this.indexedAt,
    required this.createdAt,
    this.updatedAt,
  });

  factory DocumentModel.fromJson(Map<String, dynamic> json) =>
      _$DocumentModelFromJson(json);

  Map<String, dynamic> toJson() => _$DocumentModelToJson(this);

  DocumentModel copyWith({
    int? id,
    int? knowledgeBaseId,
    String? title,
    String? content,
    String? contentType,
    Map<String, dynamic>? metadata,
    List<String>? tags,
    String? filePath,
    int? fileSize,
    DateTime? indexedAt,
    DateTime? createdAt,
    DateTime? updatedAt,
  }) {
    return DocumentModel(
      id: id ?? this.id,
      knowledgeBaseId: knowledgeBaseId ?? this.knowledgeBaseId,
      title: title ?? this.title,
      content: content ?? this.content,
      contentType: contentType ?? this.contentType,
      metadata: metadata ?? this.metadata,
      tags: tags ?? this.tags,
      filePath: filePath ?? this.filePath,
      fileSize: fileSize ?? this.fileSize,
      indexedAt: indexedAt ?? this.indexedAt,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
    );
  }

  @override
  List<Object?> get props => [
        id,
        knowledgeBaseId,
        title,
        content,
        contentType,
        metadata,
        tags,
        filePath,
        fileSize,
        indexedAt,
        createdAt,
        updatedAt,
      ];
}
