import 'package:dio/dio.dart';
import 'package:get_it/get_it.dart';

import '../app/config/app_config.dart';
import '../utils/logger.dart';
import '../services/service_locator.dart';

abstract class ApiService {
  Future<Response<dynamic>> get(
    String path, {
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  });

  Future<Response<dynamic>> post(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  });

  Future<Response<dynamic>> put(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  });

  Future<Response<dynamic>> patch(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  });

  Future<Response<dynamic>> delete(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  });

  Future<Response> download(
    String urlPath,
    String savePath, {
    ProgressCallback? onReceiveProgress,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  });
}

class ApiServiceImpl implements ApiService {
  final Dio _dio;
  final AppLogger _logger = sl<AppLogger>();

  ApiServiceImpl(this._dio);

  @override
  Future<Response<dynamic>> get(
    String path, {
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  }) async {
    try {
      _logger.d('GET Request: $path');
      if (queryParameters != null) {
        _logger.d('Query Parameters: $queryParameters');
      }

      final response = await _dio.get(
        path,
        queryParameters: queryParameters,
        options: options,
        cancelToken: cancelToken,
      );

      _logger.d('GET Response: ${response.statusCode} - ${path}');
      return response;
    } catch (e) {
      _logger.e('GET Error: $path', e);
      rethrow;
    }
  }

  @override
  Future<Response<dynamic>> post(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  }) async {
    try {
      _logger.d('POST Request: $path');
      if (data != null) {
        _logger.d('Request Data: $data');
      }
      if (queryParameters != null) {
        _logger.d('Query Parameters: $queryParameters');
      }

      final response = await _dio.post(
        path,
        data: data,
        queryParameters: queryParameters,
        options: options,
        cancelToken: cancelToken,
      );

      _logger.d('POST Response: ${response.statusCode} - ${path}');
      return response;
    } catch (e) {
      _logger.e('POST Error: $path', e);
      rethrow;
    }
  }

  @override
  Future<Response<dynamic>> put(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  }) async {
    try {
      _logger.d('PUT Request: $path');
      if (data != null) {
        _logger.d('Request Data: $data');
      }

      final response = await _dio.put(
        path,
        data: data,
        queryParameters: queryParameters,
        options: options,
        cancelToken: cancelToken,
      );

      _logger.d('PUT Response: ${response.statusCode} - ${path}');
      return response;
    } catch (e) {
      _logger.e('PUT Error: $path', e);
      rethrow;
    }
  }

  @override
  Future<Response<dynamic>> patch(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  }) async {
    try {
      _logger.d('PATCH Request: $path');
      if (data != null) {
        _logger.d('Request Data: $data');
      }

      final response = await _dio.patch(
        path,
        data: data,
        queryParameters: queryParameters,
        options: options,
        cancelToken: cancelToken,
      );

      _logger.d('PATCH Response: ${response.statusCode} - ${path}');
      return response;
    } catch (e) {
      _logger.e('PATCH Error: $path', e);
      rethrow;
    }
  }

  @override
  Future<Response<dynamic>> delete(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  }) async {
    try {
      _logger.d('DELETE Request: $path');

      final response = await _dio.delete(
        path,
        data: data,
        queryParameters: queryParameters,
        options: options,
        cancelToken: cancelToken,
      );

      _logger.d('DELETE Response: ${response.statusCode} - ${path}');
      return response;
    } catch (e) {
      _logger.e('DELETE Error: $path', e);
      rethrow;
    }
  }

  @override
  Future<Response> download(
    String urlPath,
    String savePath, {
    ProgressCallback? onReceiveProgress,
    Map<String, dynamic>? queryParameters,
    Options? options,
    CancelToken? cancelToken,
  }) async {
    try {
      _logger.d('DOWNLOAD Request: $urlPath -> $savePath');

      final response = await _dio.download(
        urlPath,
        savePath,
        onReceiveProgress: onReceiveProgress,
        queryParameters: queryParameters,
        options: options,
        cancelToken: cancelToken,
      );

      _logger.d('DOWNLOAD Response: ${response.statusCode} - $urlPath');
      return response;
    } catch (e) {
      _logger.e('DOWNLOAD Error: $urlPath', e);
      rethrow;
    }
  }
}