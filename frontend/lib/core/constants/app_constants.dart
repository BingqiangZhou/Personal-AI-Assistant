class AppConstants {
  // App info
  static const String appName = 'Personal AI Assistant';
  static const String appVersion = '1.0.0';

  // API - baseUrl is now dynamically configured via AppConfig
  static const String apiVersion = 'v1';
  static const String apiPath = '/api/$apiVersion';

  // Endpoints (use with configured baseUrl)
  static const String authPath = '$apiPath/auth';
  static const String subscriptionPath = '$apiPath/subscriptions';
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
  static const List<String> supportedDocumentTypes = [
    'pdf',
    'doc',
    'docx',
    'txt',
  ];
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

  static const Duration connectTimeout = Duration(seconds: 300);
  static const Duration receiveTimeout = Duration(seconds: 300);
  static const Duration sendTimeout = Duration(seconds: 300);
}

// App Update Constants / 应用更新常量
class AppUpdateConstants {
  // GitHub Configuration / GitHub 配置
  static const String githubOwner = 'BingqiangZhou';
  static const String githubRepo = 'Personal-AI-Assistant';
  static const String githubApiBaseUrl = 'https://api.github.com';

  // GitHub API Endpoints / GitHub API 端点
  static String get githubLatestReleaseUrl =>
      '$githubApiBaseUrl/repos/$githubOwner/$githubRepo/releases/latest';

  // Cache Configuration / 缓存配置
  static const Duration updateCheckCacheDuration = Duration(hours: 24);
  static const Duration updateCheckTimeout = Duration(seconds: 10);
  static const int updateCheckIntervalHours = 24;

  // Storage Keys / 存储键
  static const String lastUpdateCheckKey = 'last_update_check_timestamp';
  static const String cachedReleaseKey = 'cached_github_release';
  static const String skippedVersionKey = 'skipped_update_version';
}
