class AppConstants {
  // App info
  static const String appName = 'Personal AI Assistant';
  static const String appVersion = '1.0.0';

  // API
  static const String baseUrl = 'http://localhost:8000';
  static const String apiVersion = 'v1';
  static const String apiPath = '/api/$apiVersion';

  // Endpoints
  static const String authPath = '$apiPath/auth';
  static const String subscriptionPath = '$apiPath/subscriptions';
  static const String knowledgePath = '$apiPath/knowledge';
  static const String assistantPath = '$apiPath/assistant';
  static const String multimediaPath = '$apiPath/multimedia';

  // Storage keys
  static const String tokenKey = 'auth_token';
  static const String refreshTokenKey = 'refresh_token';
  static const String userKey = 'user_data';
  static const String themeKey = 'theme_mode';
  static const String localeKey = 'locale';

  // Pagination
  static const int defaultPageSize = 20;
  static const int maxPageSize = 100;

  // Cache
  static const Duration cacheDuration = Duration(hours: 1);
  static const int maxCacheSize = 100; // MB

  // File upload
  static const int maxFileSize = 10 * 1024 * 1024; // 10MB
  static const List<String> supportedImageTypes = ['jpg', 'jpeg', 'png', 'gif'];
  static const List<String> supportedDocumentTypes = ['pdf', 'doc', 'docx', 'txt'];
  static const List<String> supportedAudioTypes = ['mp3', 'wav', 'm4a'];
  static const List<String> supportedVideoTypes = ['mp4', 'mov', 'avi'];

  // UI
  static const double defaultPadding = 16.0;
  static const double defaultRadius = 12.0;
  static const Duration animationDuration = Duration(milliseconds: 300);
}

class ApiConstants {
  static const Map<String, String> headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  };

  static const Duration connectTimeout = Duration(seconds: 30);
  static const Duration receiveTimeout = Duration(seconds: 30);
  static const Duration sendTimeout = Duration(seconds: 30);
}