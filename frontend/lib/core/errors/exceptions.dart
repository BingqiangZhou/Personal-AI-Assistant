import 'package:dio/dio.dart';

abstract class AppException implements Exception {
  final String message;
  final String? code;
  final int? statusCode;

  const AppException(
    this.message, {
    this.code,
    this.statusCode,
  });

  @override
  String toString() => message;
}

class ServerException extends AppException {
  const ServerException(
    super.message, {
    super.code,
    super.statusCode,
  });

  factory ServerException.fromDioError(DioException error) {
    final message = error.response?.data?['detail'] ??
        error.response?.data?['message'] ??
        error.message ??
        'Unknown error occurred';

    final code = error.response?.data?['code'];
    final statusCode = error.response?.statusCode;

    return ServerException(
      message,
      code: code,
      statusCode: statusCode,
    );
  }
}

class NetworkException extends AppException {
  const NetworkException(
    super.message, {
    super.code,
  });

  factory NetworkException.fromDioError(DioException error) {
    switch (error.type) {
      case DioExceptionType.connectionTimeout:
      case DioExceptionType.sendTimeout:
      case DioExceptionType.receiveTimeout:
        return const NetworkException('Connection timeout');
      case DioExceptionType.badResponse:
        return ServerException.fromDioError(error);
      case DioExceptionType.cancel:
        return const NetworkException('Request cancelled');
      case DioExceptionType.unknown:
        return NetworkException(
          error.message ?? 'Unknown network error',
        );
      default:
        return const NetworkException('Unknown network error');
    }
  }
}

class CacheException extends AppException {
  const CacheException(
    super.message, {
    super.code,
  });
}

class ValidationException extends AppException {
  final Map<String, List<String>>? fieldErrors;

  const ValidationException(
    super.message, {
    this.fieldErrors,
    super.code,
  });

  factory ValidationException.fromDioError(DioException error) {
    final data = error.response?.data;

    return ValidationException(
      data?['detail'] ?? data?['message'] ?? 'Validation error',
      fieldErrors: data?['errors'] != null
          ? Map<String, List<String>>.from(data['errors'])
          : null,
      code: data?['code'],
    );
  }
}

class AuthenticationException extends AppException {
  const AuthenticationException(
    super.message, {
    super.code,
  });

  factory AuthenticationException.fromDioError(DioException error) {
    final message = error.response?.data?['detail'] ??
        error.response?.data?['message'] ??
        'Authentication failed';

    return AuthenticationException(message);
  }
}

class AuthorizationException extends AppException {
  const AuthorizationException(
    super.message, {
    super.code,
  });

  factory AuthorizationException.fromDioError(DioException error) {
    final message = error.response?.data?['detail'] ??
        error.response?.data?['message'] ??
        'Access denied';

    return AuthorizationException(message);
  }
}

class NotFoundException extends AppException {
  const NotFoundException(
    super.message, {
    super.code,
  });

  factory NotFoundException.fromDioError(DioException error) {
    final message = error.response?.data?['detail'] ??
        error.response?.data?['message'] ??
        'Resource not found';

    return NotFoundException(message);
  }
}

class UnknownException extends AppException {
  const UnknownException(
    super.message, {
    super.code,
    super.statusCode,
  });
}