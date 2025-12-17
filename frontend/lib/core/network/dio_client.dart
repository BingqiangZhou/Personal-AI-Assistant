import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../constants/app_constants.dart';
import '../errors/exceptions.dart';

class DioClient {
  late final Dio _dio;
  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage();

  DioClient() {
    _dio = Dio(BaseOptions(
      baseUrl: AppConstants.baseUrl,
      headers: ApiConstants.headers,
      connectTimeout: ApiConstants.connectTimeout,
      receiveTimeout: ApiConstants.receiveTimeout,
      sendTimeout: ApiConstants.sendTimeout,
    ));

    // Add interceptors
    _dio.interors.add(
      InterceptorsWrapper(
        onRequest: _onRequest,
        onResponse: _onResponse,
        onError: _onError,
      ),
    );
  }

  Dio get dio => _dio;

  Future<void> _onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    // Add authentication token if available
    final token = await _secureStorage.read(key: AppConstants.tokenKey);
    if (token != null) {
      options.headers['Authorization'] = 'Bearer $token';
    }

    handler.next(options);
  }

  void _onResponse(
    Response response,
    ResponseInterceptorHandler handler,
  ) {
    handler.next(response);
  }

  void _onError(
    DioException error,
    ErrorInterceptorHandler handler,
  ) {
    switch (error.type) {
      case DioExceptionType.connectionTimeout:
      case DioExceptionType.sendTimeout:
      case DioExceptionType.receiveTimeout:
        handler.reject(
          DioException(
            requestOptions: error.requestOptions,
            type: DioExceptionType.unknown,
            error: NetworkException('Connection timeout'),
          ),
        );
        break;
      case DioExceptionType.badResponse:
        final statusCode = error.response?.statusCode;
        if (statusCode != null) {
          if (statusCode >= 400 && statusCode < 500) {
            if (statusCode == 401) {
              handler.reject(
                DioException(
                  requestOptions: error.requestOptions,
                  response: error.response,
                  type: DioExceptionType.badResponse,
                  error: AuthenticationException.fromDioError(error),
                ),
              );
            } else if (statusCode == 403) {
              handler.reject(
                DioException(
                  requestOptions: error.requestOptions,
                  response: error.response,
                  type: DioExceptionType.badResponse,
                  error: AuthorizationException.fromDioError(error),
                ),
              );
            } else if (statusCode == 404) {
              handler.reject(
                DioException(
                  requestOptions: error.requestOptions,
                  response: error.response,
                  type: DioExceptionType.badResponse,
                  error: NotFoundException.fromDioError(error),
                ),
              );
            } else if (statusCode == 422) {
              handler.reject(
                DioException(
                  requestOptions: error.requestOptions,
                  response: error.response,
                  type: DioExceptionType.badResponse,
                  error: ValidationException.fromDioError(error),
                ),
              );
            } else {
              handler.reject(
                DioException(
                  requestOptions: error.requestOptions,
                  response: error.response,
                  type: DioExceptionType.badResponse,
                  error: ServerException.fromDioError(error),
                ),
              );
            }
          } else {
            handler.reject(
              DioException(
                requestOptions: error.requestOptions,
                response: error.response,
                type: DioExceptionType.badResponse,
                error: ServerException.fromDioError(error),
              ),
            );
          }
        } else {
          handler.reject(
            DioException(
              requestOptions: error.requestOptions,
              type: DioExceptionType.unknown,
              error: const UnknownException('Unknown error occurred'),
            ),
          );
        }
        break;
      default:
        handler.reject(
          DioException(
            requestOptions: error.requestOptions,
            type: DioExceptionType.unknown,
            error: NetworkException.fromDioError(error),
          ),
        );
    }
  }
}