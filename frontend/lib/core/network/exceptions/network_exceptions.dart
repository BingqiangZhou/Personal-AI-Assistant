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
        final data = error.response?.data;
        String message = 'Server error';

        if (data is Map) {
          message = data['detail']?.toString() ??
                    data['message']?.toString() ??
                    'Server error';
        } else if (data is String) {
          message = data;
        }

        return NetworkException(message);
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
    // Handle different response data formats
    String message = 'Server error';
    int? statusCode = error.response?.statusCode;

    final data = error.response?.data;
    if (data is Map) {
      // Try common field names: detail, message, error
      message = data['detail']?.toString() ??
                data['message']?.toString() ??
                data['error']?.toString() ??
                'Server error';
    } else if (data is String) {
      message = data;
    }

    return ServerException(message, statusCode: statusCode);
  }
}

class AuthenticationException extends AppException {
  const AuthenticationException(String message) : super(message, statusCode: 401);

  static AuthenticationException fromDioError(DioException error) {
    final data = error.response?.data;
    String message = 'Authentication failed';

    if (data is Map) {
      message = data['detail']?.toString() ??
                data['message']?.toString() ??
                'Authentication failed';
    } else if (data is String) {
      message = data;
    }

    return AuthenticationException(message);
  }
}

class AuthorizationException extends AppException {
  const AuthorizationException(String message) : super(message, statusCode: 403);

  static AuthorizationException fromDioError(DioException error) {
    final data = error.response?.data;
    String message = 'Access denied';

    if (data is Map) {
      message = data['detail']?.toString() ??
                data['message']?.toString() ??
                'Access denied';
    } else if (data is String) {
      message = data;
    }

    return AuthorizationException(message);
  }
}

class NotFoundException extends AppException {
  const NotFoundException(String message) : super(message, statusCode: 404);

  static NotFoundException fromDioError(DioException error) {
    final data = error.response?.data;
    String message = 'Resource not found';

    if (data is Map) {
      message = data['detail']?.toString() ??
                data['message']?.toString() ??
                'Resource not found';
    } else if (data is String) {
      message = data;
    }

    return NotFoundException(message);
  }
}

class ConflictException extends AppException {
  const ConflictException(String message) : super(message, statusCode: 409);

  static ConflictException fromDioError(DioException error) {
    final data = error.response?.data;
    String message = 'Resource conflict';

    if (data is Map) {
      message = data['detail']?.toString() ??
                data['message']?.toString() ??
                'Resource conflict';
    } else if (data is String) {
      message = data;
    }

    return ConflictException(message);
  }
}

class ValidationException extends AppException {
  final Map<String, dynamic>? fieldErrors;

  const ValidationException(String message, {this.fieldErrors})
      : super(message, statusCode: 422);

  static ValidationException fromDioError(DioException error) {
    final data = error.response?.data;
    String message = 'Validation failed';

    if (data is Map) {
      message = data['message']?.toString() ?? data['detail']?.toString() ?? 'Validation failed';
    } else if (data is String) {
      message = data;
    }

    // Parse field errors from the errors array
    Map<String, String> fieldErrors = {};
    if (data is Map && data['errors'] != null && data['errors'] is List) {
      final errors = data['errors'] as List;
      for (var error in errors) {
        if (error is! Map) continue;

        // Extract field name (remove "body -> " prefix)
        String field = error['field']?.toString() ?? '';
        if (field.startsWith('body -> ')) {
          field = field.substring(7); // Remove "body -> "
        }

        // Clean up the message (remove "Value error, " prefix)
        String errorMsg = error['message']?.toString() ?? '';
        if (errorMsg.startsWith('Value error, ')) {
          errorMsg = errorMsg.substring(13); // Remove "Value error, "
        }

        fieldErrors[field] = errorMsg;
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