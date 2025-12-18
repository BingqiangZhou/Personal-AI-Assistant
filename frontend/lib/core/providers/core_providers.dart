import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:dio/dio.dart';

import '../network/dio_client.dart';
import '../network/api_services.dart';

// Dio Client Provider
final dioClientProvider = Provider<DioClient>((ref) {
  return DioClient();
});

// API Services Provider
final apiServiceProvider = Provider<ApiServices>((ref) {
  final dioClient = ref.watch(dioClientProvider);
  return ApiServices(dioClient.dio);
});

// Current Date/Time Provider
final dateTimeProvider = Provider<DateTime>((ref) {
  return DateTime.now();
});

// App Loading State Provider
final appLoadingProvider = NotifierProvider<AppLoadingNotifier, bool>(AppLoadingNotifier.new);

class AppLoadingNotifier extends Notifier<bool> {
  @override
  bool build() {
    return false;
  }

  void setLoading(bool loading) {
    state = loading;
  }
}

// Connection Status Provider
final connectionStatusProvider = NotifierProvider<ConnectionStatusNotifier, bool>(ConnectionStatusNotifier.new);

class ConnectionStatusNotifier extends Notifier<bool> {
  @override
  bool build() {
    return true;
  }

  void setStatus(bool status) {
    state = status;
  }
}

// Error State Provider
final errorProvider = NotifierProvider<ErrorNotifier, String?>(ErrorNotifier.new);

class ErrorNotifier extends Notifier<String?> {
  @override
  String? build() {
    return null;
  }

  void setError(String? error) {
    state = error;
  }

  void clearError() {
    state = null;
  }
}

