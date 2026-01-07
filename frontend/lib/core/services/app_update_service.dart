import 'dart:io';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:personal_ai_assistant/core/constants/app_constants.dart';
import 'package:personal_ai_assistant/shared/models/github_release.dart';

/// App Update Service / 应用更新服务
///
/// Checks for app updates from GitHub releases.
/// Handles caching, error recovery, and platform-specific downloads.
/// Supports native background download on Android.
class AppUpdateService {
  AppUpdateService() {
    if (Platform.isAndroid) {
      _setupMethodChannel();
    }
  }

  static const MethodChannel _channel =
      MethodChannel('com.example.personal_ai_assistant/app_update');

  /// Get current app version
  ///
  /// Returns the version from pubspec.yaml using package_info_plus
  static Future<String> getCurrentVersion() async {
    try {
      final packageInfo = await PackageInfo.fromPlatform();
      debugPrint('📱 [APP VERSION] Package info loaded:');
      debugPrint('📱 [APP VERSION] ├─ Version: ${packageInfo.version}');
      debugPrint('📱 [APP VERSION] ├─ Build number: ${packageInfo.buildNumber}');
      debugPrint('📱 [APP VERSION] ├─ App name: ${packageInfo.appName}');
      debugPrint('📱 [APP VERSION] └─ Package name: ${packageInfo.packageName}');
      return packageInfo.version;
    } catch (e) {
      debugPrint('❌ [APP VERSION] Error getting package info: $e');
      // Fallback to a default version if package_info fails
      return '0.0.0';
    }
  }

  /// Get current app version (synchronous fallback)
  ///
  /// This is a fallback method that returns a cached version or default
  /// Use getCurrentVersion() for the actual version
  static String getCurrentVersionSync() {
    // Note: This is a fallback. The actual version should be fetched asynchronously
    // This is kept for compatibility with existing code that needs sync access
    return '0.0.2'; // Update this when publishing new releases
  }

  /// Get current platform name
  static String getCurrentPlatform() {
    if (kIsWeb) {
      return 'web';
    } else if (Platform.isWindows) {
      return 'windows';
    } else if (Platform.isMacOS) {
      return 'macos';
    } else if (Platform.isLinux) {
      return 'linux';
    } else if (Platform.isAndroid) {
      return 'android';
    } else if (Platform.isIOS) {
      return 'ios';
    }
    return 'unknown';
  }

  /// Check for updates
  ///
  /// Returns the latest release if a newer version is available,
  /// null if up to date or on error.
  Future<GitHubRelease?> checkForUpdates({
    bool forceRefresh = false,
    bool includePrerelease = false,
  }) async {
    try {
      // Get current version once (async)
      final currentVersion = await getCurrentVersion();
      debugPrint('🔄 [UPDATE CHECK] Current version: $currentVersion');
      debugPrint('🔄 [UPDATE CHECK] Platform: ${getCurrentPlatform()}');
      debugPrint('🔄 [UPDATE CHECK] Force refresh: $forceRefresh');

      // Check cache first (unless force refresh)
      if (!forceRefresh) {
        final isValid = await GitHubReleaseCache.isCacheValid();
        debugPrint('🔄 [UPDATE CHECK] Cache valid: $isValid');
        if (isValid) {
          final cached = await GitHubReleaseCache.get();
          if (cached != null) {
            debugPrint('🔄 [UPDATE CHECK] Cached version: ${cached.version}');
            if (cached.isNewerThan(currentVersion)) {
              debugPrint('🔄 [UPDATE CHECK] ✅ Cached version is newer!');
              // Also check if this version was skipped
              final skippedVersion = await GitHubReleaseCache.getSkippedVersion();
              if (skippedVersion != null && skippedVersion == cached.version) {
                debugPrint('🔄 [UPDATE CHECK] ⏭️ Version was skipped by user');
                // User skipped this version, don't notify again
                return null;
              }
              return cached;
            } else {
              debugPrint('🔄 [UPDATE CHECK] ✅ Cached version is not newer');
            }
          }
        }
      }

      // Fetch from GitHub API
      debugPrint('🔄 [UPDATE CHECK] Fetching from GitHub API...');
      debugPrint('🔄 [UPDATE CHECK] URL: ${AppUpdateConstants.githubLatestReleaseUrl}');

      final dio = Dio(BaseOptions(
        connectTimeout: AppUpdateConstants.updateCheckTimeout,
        receiveTimeout: AppUpdateConstants.updateCheckTimeout,
      ));

      final response = await dio.get(
        AppUpdateConstants.githubLatestReleaseUrl,
        options: Options(
          headers: {
            'Accept': 'application/vnd.github.v3+json',
          },
        ),
      );

      if (response.statusCode == 200 && response.data != null) {
        final release = GitHubRelease.fromJson(response.data as Map<String, dynamic>);

        // Print GitHub release info
        debugPrint('🔄 [UPDATE CHECK] ┌─────────────────────────────────────');
        debugPrint('🔄 [UPDATE CHECK] 📦 GitHub Release Info:');
        debugPrint('🔄 [UPDATE CHECK] ├─ Tag: ${release.tagName}');
        debugPrint('🔄 [UPDATE CHECK] ├─ Version: ${release.version}');
        debugPrint('🔄 [UPDATE CHECK] ├─ Name: ${release.name}');
        debugPrint('🔄 [UPDATE CHECK] ├─ Pre-release: ${release.prerelease}');
        debugPrint('🔄 [UPDATE CHECK] ├─ Draft: ${release.draft}');
        debugPrint('🔄 [UPDATE CHECK] ├─ Published: ${release.publishedAt}');
        debugPrint('🔄 [UPDATE CHECK] ├─ Assets count: ${release.assets.length}');
        if (release.assets.isNotEmpty) {
          debugPrint('🔄 [UPDATE CHECK] ├─ First asset: ${release.assets.first.name}');
          debugPrint('🔄 [UPDATE CHECK] ├─ Download URL: ${release.assets.first.downloadUrl}');
        }
        debugPrint('🔄 [UPDATE CHECK] └─────────────────────────────────────');

        // Filter out prereleases if not requested
        if (!includePrerelease && release.prerelease) {
          debugPrint('🔄 [UPDATE CHECK] ⚠️ Pre-release skipped (includePrerelease=$includePrerelease)');
          return null;
        }

        // Cache the result
        await GitHubReleaseCache.save(release);
        debugPrint('🔄 [UPDATE CHECK] 💾 Cached to local storage');

        // Check if newer than current version
        debugPrint('🔄 [UPDATE CHECK] 🔍 Comparing versions:');
        debugPrint('🔄 [UPDATE CHECK]    Current:  $currentVersion');
        debugPrint('🔄 [UPDATE CHECK]    Latest:   ${release.version}');
        debugPrint('🔄 [UPDATE CHECK]    Is Newer: ${release.isNewerThan(currentVersion)}');

        if (release.isNewerThan(currentVersion)) {
          debugPrint('🔄 [UPDATE CHECK] 🎉 NEW VERSION AVAILABLE!');
          // Also check if this version was skipped
          final skippedVersion = await GitHubReleaseCache.getSkippedVersion();
          if (skippedVersion != null && skippedVersion == release.version) {
            debugPrint('🔄 [UPDATE CHECK] ⏭️ Version was skipped by user');
            return null;
          }
          return release;
        } else {
          debugPrint('🔄 [UPDATE CHECK] ✅ App is up to date!');
        }
      }

      return null;
    } on DioException catch (e) {
      debugPrint('❌ [UPDATE CHECK] Network error: ${e.message}');
      debugPrint('❌ [UPDATE CHECK] Error type: ${e.type}');
      debugPrint('❌ [UPDATE CHECK] Response: ${e.response}');
      // If network error, return cached result if available
      final cached = await GitHubReleaseCache.get();
      final currentVersion = await getCurrentVersion();
      if (cached != null && cached.isNewerThan(currentVersion)) {
        debugPrint('❌ [UPDATE CHECK] 📦 Using cached version due to network error');
        return cached;
      }
      return null;
    } catch (e) {
      debugPrint('❌ [UPDATE CHECK] Unexpected error: $e');
      return null;
    }
  }

  /// Mark a version as skipped
  Future<void> skipVersion(String version) async {
    await GitHubReleaseCache.saveSkippedVersion(version);
  }

  /// Clear skipped version (called when user manually checks for updates)
  Future<void> clearSkippedVersion() async {
    await GitHubReleaseCache.clearSkippedVersion();
  }

  /// Get download URL for current platform
  String? getDownloadUrl(GitHubRelease release) {
    final platform = getCurrentPlatform();
    return release.getDownloadUrlForPlatform(platform);
  }

  /// Get available platforms from release assets
  List<String> getAvailablePlatforms(GitHubRelease release) {
    final platforms = <String>{};

    for (final asset in release.assets) {
      final name = asset.name.toLowerCase();
      if (name.contains('windows') || name.contains('exe')) {
        platforms.add('windows');
      } else if (name.contains('macos') || name.contains('darwin') || name.contains('dmg')) {
        platforms.add('macos');
      } else if (name.contains('linux') || name.contains('appimage') || name.contains('deb')) {
        platforms.add('linux');
      } else if (name.contains('android') || name.contains('apk')) {
        platforms.add('android');
      } else if (name.contains('ios') || name.contains('ipa')) {
        platforms.add('ios');
      } else if (name.contains('web')) {
        platforms.add('web');
      }
    }

    return platforms.toList()..sort();
  }

  /// Parse release notes to extract key information
  static List<String> parseReleaseNotes(String body) {
    final lines = body.split('\n');
    final notes = <String>[];

    for (final line in lines) {
      final trimmed = line.trim();
      if (trimmed.isEmpty) continue;

      // Remove markdown formatting
      String cleaned = trimmed
          .replaceAll(RegExp(r'^#+\s*'), '') // Remove headers
          .replaceAll(RegExp(r'\*\*([^*]+)\*\*'), r'\1') // Remove bold
          .replaceAll(RegExp(r'\*([^*]+)\*'), r'\1') // Remove italic
          .replaceAll(RegExp(r'^-\s*'), '• '); // Convert bullets

      if (cleaned.startsWith('•')) {
        notes.add(cleaned);
      } else if (cleaned.isNotEmpty) {
        notes.add(cleaned);
      }

      // Limit to reasonable number of notes
      if (notes.length >= 20) break;
    }

    return notes;
  }

  /// Setup MethodChannel for native communication
  void _setupMethodChannel() {
    _channel.setMethodCallHandler((call) async {
      debugPrint('AppUpdateService: Received method call ${call.method}');
      // Handle callbacks from native if needed
      // For now, the native service handles everything autonomously
    });
  }

  /// Start native background download (Android only)
  ///
  /// Downloads APK in background with foreground service showing progress.
  /// Automatically installs APK when download completes.
  ///
  /// Returns true if download started successfully, false otherwise.
  Future<bool> startBackgroundDownload({
    required String downloadUrl,
    String? fileName,
  }) async {
    if (!Platform.isAndroid) {
      debugPrint('⚠️ [DOWNLOAD] Background download is only supported on Android');
      return false;
    }

    final finalFileName = fileName ?? _generateFileName(downloadUrl);

    try {
      debugPrint('📥 [DOWNLOAD] Starting background download...');
      debugPrint('📥 [DOWNLOAD] ├─ URL: $downloadUrl');
      debugPrint('📥 [DOWNLOAD] ├─ File: $finalFileName');
      debugPrint('📥 [DOWNLOAD] └─ Platform: Android');

      final result = await _channel.invokeMethod('startDownload', {
        'downloadUrl': downloadUrl,
        'fileName': finalFileName,
      });

      if (result == true) {
        debugPrint('✅ [DOWNLOAD] Download service started successfully');
        debugPrint('✅ [DOWNLOAD] Check notification bar for progress');
      } else {
        debugPrint('❌ [DOWNLOAD] Download service returned false');
      }

      return result == true;
    } on PlatformException catch (e) {
      debugPrint('❌ [DOWNLOAD] Platform exception: ${e.message}');
      debugPrint('❌ [DOWNLOAD] Error code: ${e.code}');
      debugPrint('❌ [DOWNLOAD] Error details: ${e.details}');
      return false;
    } catch (e) {
      debugPrint('❌ [DOWNLOAD] Unexpected error: $e');
      return false;
    }
  }

  /// Generate filename from download URL
  String _generateFileName(String url) {
    final uri = Uri.parse(url);
    final pathSegments = uri.pathSegments;
    if (pathSegments.isNotEmpty) {
      final filename = pathSegments.last;
      if (filename.endsWith('.apk')) {
        return filename;
      }
    }
    return 'app_update_${DateTime.now().millisecondsSinceEpoch}.apk';
  }

  /// Check if background download is supported (Android only)
  static bool get supportsBackgroundDownload => Platform.isAndroid;
}
