import 'package:flutter/foundation.dart';
import 'package:get_it/get_it.dart';

final sl = GetIt.instance;

class ServiceLocator {
  static Future<void> init() async {
    // Initialize Core Services
    // Note: Hive and WindowManager are not currently in pubspec.yaml
    // If you need them, please add them to dependencies first.

    debugPrint('ServiceLocator initialized');
    
    // TODO: Register services here
    // sl.registerLazySingleton(() => SharedPrefService());
    // sl.registerLazySingleton(() => DioClient());
  }
}
