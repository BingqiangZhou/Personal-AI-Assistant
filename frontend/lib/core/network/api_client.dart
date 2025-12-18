import 'package:dio/dio.dart';
import 'package:get_it/get_it.dart';

import 'api_service.dart';
import 'exceptions/network_exceptions.dart';
import 'models/api_response.dart';

final sl = GetIt.instance;

abstract class ApiClient {
  final ApiService _apiService;
  final String _basePath;

  ApiClient(this._basePath) : _apiService = sl<ApiService>();

  Future<ApiResponse<T>> _handleRequest<T>(
    Future<Response<dynamic>> Function() request,
    T Function(dynamic json) fromJson,
  ) async {
    try {
      final response = await request();

      if (response.statusCode == 200 || response.statusCode == 201) {
        final apiResponse = ApiResponse<T>.fromJson(
          response.data,
          (json) => fromJson(json),
        );
        return apiResponse;
      } else {
        throw ServerException(
          response.data?['message'] ?? 'Server error',
          statusCode: response.statusCode,
        );
      }
    } on DioException catch (e) {
      throw _handleDioError(e);
    } catch (e) {
      throw UnknownException(e.toString());
    }
  }

  Future<PaginatedResponse<T>> _handlePaginatedRequest<T>(
    Future<Response<dynamic>> Function() request,
    T Function(dynamic json) fromJson,
  ) async {
    try {
      final response = await request();

      if (response.statusCode == 200) {
        final data = response.data as Map<String, dynamic>;
        final items = (data['items'] as List)
            .map((json) => fromJson(json))
            .toList();

        return PaginatedResponse<T>(
          items: items,
          page: data['page'] ?? 1,
          pageSize: data['page_size'] ?? 20,
          total: data['total'] ?? items.length,
          totalPages: data['total_pages'] ?? 1,
        );
      } else {
        throw ServerException(
          response.data?['message'] ?? 'Server error',
          statusCode: response.statusCode,
        );
      }
    } on DioException catch (e) {
      throw _handleDioError(e);
    } catch (e) {
      throw UnknownException(e.toString());
    }
  }

  AppException _handleDioError(DioException error) {
    switch (error.type) {
      case DioExceptionType.connectionTimeout:
      case DioExceptionType.sendTimeout:
      case DioExceptionType.receiveTimeout:
        return const NetworkException('Connection timeout');
      case DioExceptionType.badResponse:
        final statusCode = error.response?.statusCode;
        switch (statusCode) {
          case 401:
            return AuthenticationException.fromDioError(error);
          case 403:
            return AuthorizationException.fromDioError(error);
          case 404:
            return NotFoundException.fromDioError(error);
          case 422:
            return ValidationException.fromDioError(error);
          default:
            if (statusCode != null && statusCode >= 500) {
              return ServerException.fromDioError(error);
            }
            return NetworkException.fromDioError(error);
        }
      case DioExceptionType.connectionError:
        return const NetworkException('No internet connection');
      case DioExceptionType.badCertificate:
        return const NetworkException('SSL certificate error');
      case DioExceptionType.cancel:
        return const NetworkException('Request cancelled');
      case DioExceptionType.unknown:
        return NetworkException.fromDioError(error);
    }
  }

  // HTTP Methods
  Future<ApiResponse<T>> get<T>(
    String path, {
    Map<String, dynamic>? queryParameters,
    required T Function(dynamic json) fromJson,
  }) {
    return _handleRequest(
      () => _apiService.get('$_basePath$path', queryParameters: queryParameters),
      fromJson,
    );
  }

  Future<ApiResponse<T>> post<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    required T Function(dynamic json) fromJson,
  }) {
    return _handleRequest(
      () => _apiService.post('$_basePath$path', data: data, queryParameters: queryParameters),
      fromJson,
    );
  }

  Future<ApiResponse<T>> put<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    required T Function(dynamic json) fromJson,
  }) {
    return _handleRequest(
      () => _apiService.put('$_basePath$path', data: data, queryParameters: queryParameters),
      fromJson,
    );
  }

  Future<ApiResponse<T>> patch<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    required T Function(dynamic json) fromJson,
  }) {
    return _handleRequest(
      () => _apiService.patch('$_basePath$path', data: data, queryParameters: queryParameters),
      fromJson,
    );
  }

  Future<ApiResponse<T>> delete<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    required T Function(dynamic json) fromJson,
  }) {
    return _handleRequest(
      () => _apiService.delete('$_basePath$path', data: data, queryParameters: queryParameters),
      fromJson,
    );
  }

  // Paginated methods
  Future<PaginatedResponse<T>> getPaginated<T>(
    String path, {
    Map<String, dynamic>? queryParameters,
    required T Function(dynamic json) fromJson,
  }) {
    return _handlePaginatedRequest(
      () => _apiService.get('$_basePath$path', queryParameters: queryParameters),
      fromJson,
    );
  }

  Future<PaginatedResponse<T>> postPaginated<T>(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    required T Function(dynamic json) fromJson,
  }) {
    return _handlePaginatedRequest(
      () => _apiService.post('$_basePath$path', data: data, queryParameters: queryParameters),
      fromJson,
    );
  }
}