import 'package:json_annotation/json_annotation.dart';

part 'api_response.g.dart';

@JsonSerializable(genericArgumentFactories: true)
class ApiResponse<T> {
  final bool success;
  final String? message;
  final T? data;
  final Map<String, dynamic>? errors;

  const ApiResponse({
    required this.success,
    this.message,
    this.data,
    this.errors,
  });

  factory ApiResponse.fromJson(
    Map<String, dynamic> json,
    T Function(Object? json) fromJsonT,
  ) =>
      _$ApiResponseFromJson(json, fromJsonT);

  Map<String, dynamic> toJson(Object Function(T value) toJsonT) =>
      _$ApiResponseToJson(this, toJsonT);

  @override
  String toString() {
    return 'ApiResponse(success: $success, message: $message, data: $data, errors: $errors)';
  }
}

@JsonSerializable(genericArgumentFactories: true)
class PaginatedResponse<T> {
  final List<T> items;
  final int page;
  final int pageSize;
  final int total;
  final int totalPages;

  const PaginatedResponse({
    required this.items,
    required this.page,
    required this.pageSize,
    required this.total,
    required this.totalPages,
  });

  factory PaginatedResponse.fromJson(
    Map<String, dynamic> json,
    T Function(Object? json) fromJsonT,
  ) =>
      _$PaginatedResponseFromJson(json, fromJsonT);

  Map<String, dynamic> toJson(Object Function(T value) toJsonT) =>
      _$PaginatedResponseToJson(this, toJsonT);

  bool get hasNextPage => page < totalPages;
  bool get hasPreviousPage => page > 1;
}