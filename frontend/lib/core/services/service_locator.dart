import 'package:get_it/get_it.dart';
import 'package:dio/dio.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../network/dio_client.dart';
import '../network/api_service.dart';
import '../storage/local_storage_service.dart';
import '../storage/secure_storage_service.dart';
import '../utils/logger.dart';

final GetIt sl = GetIt.instance;

class ServiceLocator {
  static Future<void> init() async {
    // Core services
    await _initStorage();
    _initNetwork();
    _initUtils();
  }

  static Future<void> _initStorage() async {
    // Note: Hive removed, using shared_preferences only
    // Register SharedPreferences
    final sharedPreferences = await SharedPreferences.getInstance();
    sl.registerSingleton<SharedPreferences>(sharedPreferences);

    // Register FlutterSecureStorage
    const secureStorage = FlutterSecureStorage();
    sl.registerSingleton<FlutterSecureStorage>(secureStorage);

    // Register storage services
    sl.registerLazySingleton<LocalStorageService>(
      () => LocalStorageServiceImpl(sharedPreferences),
    );
    sl.registerLazySingleton<SecureStorageService>(
      () => SecureStorageServiceImpl(secureStorage),
    );
  }

  static void _initNetwork() {
    // Register Dio
    sl.registerLazySingleton<Dio>(() => DioClient.createDio());

    // Register API service
    sl.registerLazySingleton<ApiService>(
      () => ApiServiceImpl(sl<Dio>()),
    );
  }

  static void _initUtils() {
    // Register logger
    sl.registerLazySingleton<AppLogger>(() => AppLogger());
  }
}