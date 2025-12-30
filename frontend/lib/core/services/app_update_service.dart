import 'dart:io';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:personal_ai_assistant/core/constants/app_constants.dart';
import 'package:personal_ai_assistant/shared/models/github_release.dart';

/// App Update Service / 应用更新服务
///
/// Checks for app updates from GitHub releases.
/// Handles caching, error recovery, and platform-specific downloads.
class AppUpdateService {
  AppUpdateService();

  /// Get current app version
  ///
  /// Returns the version from pubspec.yaml using package_info_plus
  static Future<String> getCurrentVersion() async {
    try {
      final packageInfo = await PackageInfo.fromPlatform();
      return packageInfo.version;
    } catch (e) {
      debugPrint('Error getting package info: $e');
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

      // Check cache first (unless force refresh)
      if (!forceRefresh) {
        final isValid = await GitHubReleaseCache.isCacheValid();
        if (isValid) {
          final cached = await GitHubReleaseCache.get();
          if (cached != null) {
            if (cached.isNewerThan(currentVersion)) {
              // Also check if this version was skipped
              final skippedVersion = await GitHubReleaseCache.getSkippedVersion();
              if (skippedVersion != null && skippedVersion == cached.version) {
                // User skipped this version, don't notify again
                return null;
              }
              return cached;
            }
          }
        }
      }

      // Fetch from GitHub API
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

        // Filter out prereleases if not requested
        if (!includePrerelease && release.prerelease) {
          return null;
        }

        // Cache the result
        await GitHubReleaseCache.save(release);

        // Check if newer than current version
        if (release.isNewerThan(currentVersion)) {
          // Also check if this version was skipped
          final skippedVersion = await GitHubReleaseCache.getSkippedVersion();
          if (skippedVersion != null && skippedVersion == release.version) {
            return null;
          }
          return release;
        }
      }

      return null;
    } on DioException catch (e) {
      debugPrint('Error checking for updates: ${e.message}');
      // If network error, return cached result if available
      final cached = await GitHubReleaseCache.get();
      final currentVersion = await getCurrentVersion();
      if (cached != null && cached.isNewerThan(currentVersion)) {
        return cached;
      }
      return null;
    } catch (e) {
      debugPrint('Unexpected error checking for updates: $e');
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
}
