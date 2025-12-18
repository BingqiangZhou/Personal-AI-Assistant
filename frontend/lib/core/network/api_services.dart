import 'package:json_annotation/json_annotation.dart';
import 'package:retrofit/retrofit.dart';
import 'package:dio/dio.dart';

import '../../features/auth/models/user_model.dart';
import '../../features/auth/models/auth_response.dart';
import '../../features/assistant/models/chat_message_model.dart';
import '../../features/assistant/models/chat_session_model.dart';
import '../../features/knowledge/models/knowledge_item_model.dart';
import '../../features/subscription/models/subscription_model.dart';

part 'api_services.g.dart';

@RestApi()
abstract class ApiServices {
  factory ApiServices(Dio dio, {String baseUrl}) = _ApiServices;

  // Authentication endpoints
  @POST('/auth/register')
  Future<AuthResponse> register(@Body() Map<String, dynamic> request);

  @POST('/auth/login')
  Future<AuthResponse> login(@Body() Map<String, dynamic> request);

  @POST('/auth/refresh')
  Future<AuthResponse> refreshToken(@Body() Map<String, dynamic> request);

  @POST('/auth/logout')
  Future<void> logout();

  @GET('/auth/me')
  Future<UserModel> getCurrentUser();

  // Chat/AI Assistant endpoints
  @GET('/assistant/sessions')
  Future<List<ChatSessionModel>> getChatSessions();

  @POST('/assistant/sessions')
  Future<ChatSessionModel> createChatSession(@Body() Map<String, dynamic> request);

  @GET('/assistant/sessions/{sessionId}')
  Future<ChatSessionModel> getChatSession(@Path() String sessionId);

  @PUT('/assistant/sessions/{sessionId}')
  Future<ChatSessionModel> updateChatSession(
    @Path() String sessionId,
    @Body() Map<String, dynamic> request,
  );

  @DELETE('/assistant/sessions/{sessionId}')
  Future<void> deleteChatSession(@Path() String sessionId);

  @GET('/assistant/sessions/{sessionId}/messages')
  Future<List<ChatMessageModel>> getChatMessages(
    @Path() String sessionId, {
    @Query('limit') int? limit,
    @Query('offset') int? offset,
  });

  @POST('/assistant/sessions/{sessionId}/messages')
  Future<ChatMessageModel> sendMessage(
    @Path() String sessionId,
    @Body() Map<String, dynamic> request,
  );

  @POST('/assistant/chat/stream')
  Future<Stream<String>> streamChat(@Body() Map<String, dynamic> request);

  // Knowledge Base endpoints
  @GET('/knowledge/items')
  Future<PaginatedResponse<KnowledgeItemModel>> getKnowledgeItems({
    @Query('page') int? page,
    @Query('limit') int? limit,
    @Query('category') String? category,
    @Query('search') String? search,
  });

  @POST('/knowledge/items')
  Future<KnowledgeItemModel> createKnowledgeItem(@Body() Map<String, dynamic> request);

  @GET('/knowledge/items/{itemId}')
  Future<KnowledgeItemModel> getKnowledgeItem(@Path() String itemId);

  @PUT('/knowledge/items/{itemId}')
  Future<KnowledgeItemModel> updateKnowledgeItem(
    @Path() String itemId,
    @Body() Map<String, dynamic> request,
  );

  @DELETE('/knowledge/items/{itemId}')
  Future<void> deleteKnowledgeItem(@Path() String itemId);

  @POST('/knowledge/items/{itemId}/files')
  Future<KnowledgeItemModel> uploadFile(
    @Path() String itemId,
    @Part(name: 'file') Map<String, dynamic> file,
  );

  @GET('/knowledge/categories')
  Future<List<Map<String, dynamic>>> getKnowledgeCategories();

  @POST('/knowledge/search')
  Future<SearchResponse<KnowledgeItemModel>> searchKnowledge(
    @Body() Map<String, dynamic> request,
  );

  // Subscription endpoints
  @GET('/subscriptions')
  Future<PaginatedResponse<SubscriptionModel>> getSubscriptions({
    @Query('page') int? page,
    @Query('limit') int? limit,
    @Query('type') String? type,
    @Query('status') String? status,
  });

  @POST('/subscriptions')
  Future<SubscriptionModel> createSubscription(@Body() Map<String, dynamic> request);

  @GET('/subscriptions/{subscriptionId}')
  Future<SubscriptionModel> getSubscription(@Path() String subscriptionId);

  @PUT('/subscriptions/{subscriptionId}')
  Future<SubscriptionModel> updateSubscription(
    @Path() String subscriptionId,
    @Body() Map<String, dynamic> request,
  );

  @DELETE('/subscriptions/{subscriptionId}')
  Future<void> deleteSubscription(@Path() String subscriptionId);

  @POST('/subscriptions/{subscriptionId}/refresh')
  Future<SubscriptionModel> refreshSubscription(@Path() String subscriptionId);

  @GET('/subscriptions/types')
  Future<List<Map<String, dynamic>>> getSubscriptionTypes();

  // Multimedia endpoints
  @POST('/multimedia/upload')
  Future<Map<String, dynamic>> uploadMediaFile(@Part(name: 'file') Map<String, dynamic> file);

  @GET('/multimedia/files/{fileId}')
  Future<Map<String, dynamic>> getFile(@Path() String fileId);

  @DELETE('/multimedia/files/{fileId}')
  Future<void> deleteFile(@Path() String fileId);

  @POST('/multimedia/process')
  Future<Map<String, dynamic>> processFile(@Body() Map<String, dynamic> request);
}

// Generic response models
@JsonSerializable(genericArgumentFactories: true)
class PaginatedResponse<T> {
  final List<T> items;
  final int totalCount;
  final int currentPage;
  final int totalPages;
  final bool hasNextPage;
  final bool hasPreviousPage;

  const PaginatedResponse({
    required this.items,
    required this.totalCount,
    required this.currentPage,
    required this.totalPages,
    required this.hasNextPage,
    required this.hasPreviousPage,
  });

  factory PaginatedResponse.fromJson(
    Map<String, dynamic> json,
    T Function(Object? json) fromJsonT,
  ) =>
      _$PaginatedResponseFromJson(json, fromJsonT);

  Map<String, dynamic> toJson(Object Function(T value) toJsonT) =>
      _$PaginatedResponseToJson(this, toJsonT);
}

@JsonSerializable(genericArgumentFactories: true)
class SearchResponse<T> {
  final List<T> results;
  final int totalCount;
  final Map<String, dynamic> facets;
  final Map<String, dynamic> metadata;

  const SearchResponse({
    required this.results,
    required this.totalCount,
    required this.facets,
    required this.metadata,
  });

  factory SearchResponse.fromJson(
    Map<String, dynamic> json,
    T Function(Object? json) fromJsonT,
  ) =>
      _$SearchResponseFromJson(json, fromJsonT);

  Map<String, dynamic> toJson(Object Function(T value) toJsonT) =>
      _$SearchResponseToJson(this, toJsonT);
}

// WebSocket service for real-time updates
abstract class WebSocketService {
  void connect();
  void disconnect();
  Stream<dynamic> get messageStream;
  void sendMessage(Map<String, dynamic> message);
}

// API error response model
@JsonSerializable()
class ApiErrorResponse {
  final String error;
  final String message;
  final int? statusCode;
  final Map<String, dynamic>? details;

  const ApiErrorResponse({
    required this.error,
    required this.message,
    this.statusCode,
    this.details,
  });

  factory ApiErrorResponse.fromJson(Map<String, dynamic> json) =>
      _$ApiErrorResponseFromJson(json);

  Map<String, dynamic> toJson() => _$ApiErrorResponseToJson(this);
}