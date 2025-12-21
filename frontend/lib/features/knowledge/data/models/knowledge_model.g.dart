// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'knowledge_model.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

KnowledgeBaseModel _$KnowledgeBaseModelFromJson(Map<String, dynamic> json) =>
    KnowledgeBaseModel(
      id: (json['id'] as num).toInt(),
      userId: (json['user_id'] as num).toInt(),
      name: json['name'] as String,
      description: json['description'] as String?,
      isPublic: json['is_public'] as bool? ?? false,
      isDefault: json['is_default'] as bool? ?? false,
      settings: json['settings'] as Map<String, dynamic>?,
      documentCount: (json['document_count'] as num?)?.toInt() ?? 0,
      createdAt: DateTime.parse(json['created_at'] as String),
      updatedAt: json['updated_at'] == null
          ? null
          : DateTime.parse(json['updated_at'] as String),
    );

Map<String, dynamic> _$KnowledgeBaseModelToJson(KnowledgeBaseModel instance) =>
    <String, dynamic>{
      'id': instance.id,
      'user_id': instance.userId,
      'name': instance.name,
      'description': instance.description,
      'is_public': instance.isPublic,
      'is_default': instance.isDefault,
      'settings': instance.settings,
      'document_count': instance.documentCount,
      'created_at': instance.createdAt.toIso8601String(),
      'updated_at': instance.updatedAt?.toIso8601String(),
    };

DocumentModel _$DocumentModelFromJson(Map<String, dynamic> json) =>
    DocumentModel(
      id: (json['id'] as num).toInt(),
      knowledgeBaseId: (json['knowledge_base_id'] as num).toInt(),
      title: json['title'] as String,
      content: json['content'] as String?,
      contentType: json['content_type'] as String,
      metadata: json['metadata'] as Map<String, dynamic>?,
      tags: (json['tags'] as List<dynamic>?)?.map((e) => e as String).toList(),
      filePath: json['file_path'] as String?,
      fileSize: (json['file_size'] as num?)?.toInt(),
      indexedAt: json['indexed_at'] == null
          ? null
          : DateTime.parse(json['indexed_at'] as String),
      createdAt: DateTime.parse(json['created_at'] as String),
      updatedAt: json['updated_at'] == null
          ? null
          : DateTime.parse(json['updated_at'] as String),
    );

Map<String, dynamic> _$DocumentModelToJson(DocumentModel instance) =>
    <String, dynamic>{
      'id': instance.id,
      'knowledge_base_id': instance.knowledgeBaseId,
      'title': instance.title,
      'content': instance.content,
      'content_type': instance.contentType,
      'metadata': instance.metadata,
      'tags': instance.tags,
      'file_path': instance.filePath,
      'file_size': instance.fileSize,
      'indexed_at': instance.indexedAt?.toIso8601String(),
      'created_at': instance.createdAt.toIso8601String(),
      'updated_at': instance.updatedAt?.toIso8601String(),
    };
