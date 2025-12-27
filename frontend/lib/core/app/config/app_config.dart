import 'dart:io';

class AppConfig {
  // Environment
  static const String environment = String.fromEnvironment(
    'ENVIRONMENT',
    defaultValue: 'development',
  );

  // API Configuration
  // API Configuration
  static String _apiBaseUrl = '';

  static String get apiBaseUrl {
    if (_apiBaseUrl.isNotEmpty) {
      return _apiBaseUrl;
    }
    
    switch (environment) {
      case 'production':
        return 'https://api.personalai.app';
      case 'staging':
        return 'https://api-staging.personalai.app';
      default:
        // Android emulator needs 10.0.2.2 to access host localhost
        if (Platform.isAndroid) {
          return 'http://10.0.2.2:8000';
        }
        return 'http://localhost:8000';
    }
  }

  static void setApiBaseUrl(String url) {
    _apiBaseUrl = url;
  }


  // App Configuration
  static const String appName = 'Personal AI Assistant';
  static const String appVersion = '1.0.0';

  // Timeouts
  static const Duration connectionTimeout = Duration(seconds: 30);
  static const Duration receiveTimeout = Duration(seconds: 30);
  static const Duration sendTimeout = Duration(seconds: 30);

  // Pagination
  static const int defaultPageSize = 20;
  static const int maxPageSize = 100;

  // Cache
  static const Duration cacheExpiration = Duration(hours: 24);
  static const int maxCacheSize = 100 * 1024 * 1024; // 100MB

  // Audio
  static const Duration audioSeekStep = Duration(seconds: 10);
  static const Duration audioFastForwardDuration = Duration(seconds: 30);
  static const Duration audioRewindDuration = Duration(seconds: 10);

  // UI
  static const double defaultBorderRadius = 12.0;
  static const double largeBorderRadius = 16.0;
  static const double smallBorderRadius = 8.0;

  // Animation
  static const Duration defaultAnimationDuration = Duration(milliseconds: 300);
  static const Duration fastAnimationDuration = Duration(milliseconds: 150);
  static const Duration slowAnimationDuration = Duration(milliseconds: 500);

  // Feature Flags
  static const bool enableAnalytics = false;
  static const bool enableCrashReporting = false;
  static const bool enablePerformanceMonitoring = false;
}

// Additional constants for compatibility
class AppConstants {
  static const String appName = AppConfig.appName;
  static const String appVersion = AppConfig.appVersion;
  static String get baseUrl => '${AppConfig.apiBaseUrl}/api/v1';
  static const int connectTimeout = 30000;
  static const int receiveTimeout = 30000;
  static const int sendTimeout = 30000;

  // Storage Keys
  static const String accessTokenKey = 'access_token';
  static const String refreshTokenKey = 'refresh_token';
  static const String userProfileKey = 'user_profile';

  // App Configuration
  static const String environment = AppConfig.environment;
  static const bool enableLogging = true;
}

class ApiConstants {
  static const Map<String, String> headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  };

  // API Endpoints
  static const String auth = '/auth';
  static const String login = '/auth/login';
  static const String register = '/auth/register';
  static const String refresh = '/auth/refresh';
  static const String logout = '/auth/logout';
  static const String profile = '/auth/me';

  static const String assistant = '/assistant';
  static const String chat = '/assistant/chat';
  static const String conversations = '/assistant/conversations';

  static const String knowledge = '/knowledge';
  static const String documents = '/knowledge/documents';
  static const String search = '/knowledge/search';

  static const String podcast = '/podcast';
  static const String feeds = '/podcast/feeds';
  static const String episodes = '/podcast/episodes';

  static const String subscription = '/subscription';
  static const String feedsSubscriptions = '/subscription/feeds';
}