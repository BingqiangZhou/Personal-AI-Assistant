import 'package:flutter/widgets.dart';
import 'package:flutter_cache_manager/flutter_cache_manager.dart';

abstract class AppCacheService {
  CacheManager get mediaCacheManager;
  Future<void> clearMediaCache();
  Future<void> clearMemoryImageCache();
  Future<void> clearAll();
  Future<FileInfo?> getCachedFileInfo(String url);
  Future<void> warmUp(String url);
}

class AppMediaCacheManager extends CacheManager {
  static const String key = 'app_media_cache';
  static final AppMediaCacheManager instance = AppMediaCacheManager._();

  AppMediaCacheManager._()
      : super(
          Config(
            key,
            stalePeriod: const Duration(days: 30),
            maxNrOfCacheObjects: 200,
          ),
        );
}

class AppCacheServiceImpl implements AppCacheService {
  @override
  CacheManager get mediaCacheManager => AppMediaCacheManager.instance;

  @override
  Future<void> clearMediaCache() async {
    await mediaCacheManager.emptyCache();
  }

  @override
  Future<void> clearMemoryImageCache() async {
    final cache = PaintingBinding.instance.imageCache;
    cache.clear();
    cache.clearLiveImages();
  }

  @override
  Future<void> clearAll() async {
    await clearMediaCache();
    await clearMemoryImageCache();
  }

  @override
  Future<FileInfo?> getCachedFileInfo(String url) async {
    return mediaCacheManager.getFileFromCache(url);
  }

  @override
  Future<void> warmUp(String url) async {
    await mediaCacheManager.downloadFile(url);
  }
}
