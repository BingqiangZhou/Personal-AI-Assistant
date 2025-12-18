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
    final data = error.response?.data;

    // Handle case where data might be a string or list instead of a map
    String message = 'Unknown error occurred';
    if (data is Map) {
      message = data['detail'] ?? data['message'] ?? error.message ?? 'Unknown error occurred';
    } else if (data is String) {
      message = data;
    } else if (data is List) {
      message = data.join(', ');
    } else {
      message = error.message ?? 'Unknown error occurred';
    }

    final code = data is Map ? data['code'] : null;
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
        // Convert ServerException to NetworkException for compatibility
        final serverException = ServerException.fromDioError(error);
        return NetworkException(
          serverException.message,
          code: serverException.code,
        );
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

    // Handle different error response structures
    Map<String, List<String>>? fieldErrors;
    if (data?['errors'] != null) {
      if (data['errors'] is Map) {
        try {
          fieldErrors = Map<String, List<String>>.from(data['errors']);
        } catch (e) {
          // Could not convert, skip field errors
        }
      } else if (data['errors'] is List) {
        // Convert list to map format: {'general': ['error1', 'error2']}
        final errorsList = data['errors'] as List;
        fieldErrors = {'general': errorsList.map((e) => e.toString()).toList()};
      }
    }

    return ValidationException(
      data?['detail'] ?? data?['message'] ?? 'Validation error',
      fieldErrors: fieldErrors,
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