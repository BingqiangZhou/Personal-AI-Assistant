import 'package:json_annotation/json_annotation.dart';
import 'package:retrofit/retrofit.dart';
import 'package:dio/dio.dart';

import '../../features/auth/models/user_model.dart';
import '../../features/auth/models/auth_response.dart';
import '../../features/subscription/models/subscription_model.dart';
import 'models/api_response.dart';

part 'api_services.g.dart';

@JsonSerializable()
class SimpleResponse {
  final String? message;
  final Map<String, dynamic>? data;

  const SimpleResponse({
    this.message,
    this.data,
  });

  factory SimpleResponse.fromJson(Map<String, dynamic> json) =>
      _$SimpleResponseFromJson(json);

  Map<String, dynamic> toJson() => _$SimpleResponseToJson(this);
}

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

  @POST('/auth/logout-all')
  Future<void> logoutAll();

  @GET('/auth/me')
  Future<UserModel> getCurrentUser();

  @POST('/auth/forgot-password')
  Future<SimpleResponse> forgotPassword(@Body() Map<String, dynamic> request);

  @POST('/auth/reset-password')
  Future<SimpleResponse> resetPassword(@Body() Map<String, dynamic> request);

  // Subscription endpoints
  @GET('/subscriptions/')
  Future<PaginatedResponse<SubscriptionModel>> getSubscriptions({
    @Query('page') int? page,
    @Query('size') int? size,
    @Query('source_type') String? sourceType,
    @Query('status') String? status,
  });

  @POST('/subscriptions/')
  Future<SubscriptionModel> createSubscription(@Body() Map<String, dynamic> request);

  @GET('/subscriptions/{subscriptionId}')
  Future<SubscriptionModel> getSubscription(@Path('subscriptionId') int subscriptionId);

  @PUT('/subscriptions/{subscriptionId}')
  Future<SubscriptionModel> updateSubscription(
    @Path('subscriptionId') int subscriptionId,
    @Body() Map<String, dynamic> request,
  );

  @DELETE('/subscriptions/{subscriptionId}')
  Future<void> deleteSubscription(@Path('subscriptionId') int subscriptionId);

  @POST('/subscriptions/{subscriptionId}/fetch')
  Future<SubscriptionModel> fetchSubscription(@Path('subscriptionId') int subscriptionId);

  @POST('/subscriptions/fetch-all')
  Future<void> fetchAllSubscriptions();
}

// WebSocket service for real-time updates
abstract class WebSocketService {
  void connect();
  void disconnect();
  Stream<dynamic> get messageStream;
  void sendMessage(Map<String, dynamic> message);
}