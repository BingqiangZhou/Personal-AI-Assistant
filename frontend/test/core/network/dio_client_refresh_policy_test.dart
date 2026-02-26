import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/network/dio_client.dart';

DioException _buildDioError({
  required DioExceptionType type,
  int? statusCode,
  dynamic data,
}) {
  final request = RequestOptions(path: '/auth/refresh', method: 'POST');
  return DioException(
    requestOptions: request,
    type: type,
    response: statusCode == null
        ? null
        : Response<dynamic>(
            requestOptions: request,
            statusCode: statusCode,
            data: data,
          ),
  );
}

void main() {
  group('DioClient refresh failure policy', () {
    test('classifies 401 refresh response as invalid session', () {
      final error = _buildDioError(
        type: DioExceptionType.badResponse,
        statusCode: 401,
        data: {'detail': 'Could not validate credentials'},
      );

      final reason = DioClient.classifyRefreshFailure(error);
      expect(reason, TokenRefreshFailureReason.invalidSession);
      expect(DioClient.shouldClearTokensForRefreshFailure(reason), isTrue);
    });

    test('classifies 404 invalid session as invalid session', () {
      final error = _buildDioError(
        type: DioExceptionType.badResponse,
        statusCode: 404,
        data: {'detail': 'Invalid session'},
      );

      final reason = DioClient.classifyRefreshFailure(error);
      expect(reason, TokenRefreshFailureReason.invalidSession);
      expect(DioClient.shouldClearTokensForRefreshFailure(reason), isTrue);
    });

    test('classifies timeout failures as transient', () {
      final error = _buildDioError(type: DioExceptionType.connectionTimeout);

      final reason = DioClient.classifyRefreshFailure(error);
      expect(reason, TokenRefreshFailureReason.transientFailure);
      expect(DioClient.shouldClearTokensForRefreshFailure(reason), isFalse);
    });

    test('classifies 503 refresh response as transient', () {
      final error = _buildDioError(
        type: DioExceptionType.badResponse,
        statusCode: 503,
        data: {'detail': 'Service unavailable'},
      );

      final reason = DioClient.classifyRefreshFailure(error);
      expect(reason, TokenRefreshFailureReason.transientFailure);
      expect(DioClient.shouldClearTokensForRefreshFailure(reason), isFalse);
    });

    test('classifies unrelated 404 response as unknown failure', () {
      final error = _buildDioError(
        type: DioExceptionType.badResponse,
        statusCode: 404,
        data: {'detail': 'Endpoint not found'},
      );

      final reason = DioClient.classifyRefreshFailure(error);
      expect(reason, TokenRefreshFailureReason.unknownFailure);
      expect(DioClient.shouldClearTokensForRefreshFailure(reason), isFalse);
    });
  });
}
