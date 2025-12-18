import 'package:dio/dio.dart';

abstract class AppException implements Exception {
  final String message;
  final int? statusCode;

  const AppException(this.message, {this.statusCode});

  @override
  String toString() => message;
}

class NetworkException extends AppException {
  const NetworkException(String message) : super(message);

  static NetworkException fromDioError(DioException error) {
    switch (error.type) {
      case DioExceptionType.connectionTimeout:
        return const NetworkException('Connection timeout');
      case DioExceptionType.sendTimeout:
        return const NetworkException('Request timeout');
      case DioExceptionType.receiveTimeout:
        return const NetworkException('Response timeout');
      case DioExceptionType.connectionError:
        return const NetworkException('No internet connection');
      case DioExceptionType.badResponse:
        return NetworkException(
          error.response?.data?['message'] ?? 'Server error',
        );
      default:
        return NetworkException(
          error.message ?? 'Network error occurred',
        );
    }
  }
}

class ServerException extends AppException {
  const ServerException(String message, {int? statusCode}) : super(message, statusCode: statusCode);

  static ServerException fromDioError(DioException error) {
    return ServerException(
      error.response?.data?['message'] ?? 'Server error',
      statusCode: error.response?.statusCode,
    );
  }
}

class AuthenticationException extends AppException {
  const AuthenticationException(String message) : super(message, statusCode: 401);

  static AuthenticationException fromDioError(DioException error) {
    return AuthenticationException(
      error.response?.data?['message'] ?? 'Authentication failed',
    );
  }
}

class AuthorizationException extends AppException {
  const AuthorizationException(String message) : super(message, statusCode: 403);

  static AuthorizationException fromDioError(DioException error) {
    return AuthorizationException(
      error.response?.data?['message'] ?? 'Access denied',
    );
  }
}

class NotFoundException extends AppException {
  const NotFoundException(String message) : super(message, statusCode: 404);

  static NotFoundException fromDioError(DioException error) {
    return NotFoundException(
      error.response?.data?['message'] ?? 'Resource not found',
    );
  }
}

class ConflictException extends AppException {
  const ConflictException(String message) : super(message, statusCode: 409);

  static ConflictException fromDioError(DioException error) {
    return ConflictException(
      error.response?.data?['detail'] ?? error.response?.data?['message'] ?? 'Resource conflict',
    );
  }
}

class ValidationException extends AppException {
  final Map<String, dynamic>? fieldErrors;

  const ValidationException(String message, {this.fieldErrors})
      : super(message, statusCode: 422);

  static ValidationException fromDioError(DioException error) {
    final data = error.response?.data;
    final message = data?['message'] ?? data?['detail'] ?? 'Validation failed';

    // Parse field errors from the errors array
    Map<String, String> fieldErrors = {};
    if (data?['errors'] != null) {
      final errors = data['errors'] as List;
      for (var error in errors) {
        // Extract field name (remove "body -> " prefix)
        String field = error['field'] ?? '';
        if (field.startsWith('body -> ')) {
          field = field.substring(7); // Remove "body -> "
        }

        // Clean up the message (remove "Value error, " prefix)
        String message = error['message'] ?? '';
        if (message.startsWith('Value error, ')) {
          message = message.substring(13); // Remove "Value error, "
        }

        fieldErrors[field] = message;
      }
    }

    return ValidationException(
      message,
      fieldErrors: fieldErrors,
    );
  }

  // Getter for compatibility with existing code
  Map<String, dynamic>? get details => fieldErrors;
}

class UnknownException extends AppException {
  const UnknownException(String message) : super(message);
}