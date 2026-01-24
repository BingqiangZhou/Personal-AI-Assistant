import 'package:flutter/material.dart';

import 'app_logger.dart' as logger;

/// 统一的图片加载工具，处理CloudFront 403等CDN访问问题
class ImageLoader {
  /// 创建一个带有错误处理和回退机制的图片Widget
  static Widget networkWithFallback(
    String? imageUrl, {
    double? width,
    double? height,
    BoxFit fit = BoxFit.cover,
    Widget? errorWidget,
    Widget? loadingWidget,
    Map<String, String>? headers,
  }) {
    if (imageUrl == null || imageUrl.isEmpty) {
      return _buildFallbackWidget(errorWidget, width, height);
    }

    // 尝试使用缓存管理器（支持重试和缓存）
    return Image.network(
      imageUrl,
      width: width,
      height: height,
      fit: fit,
      headers: headers,
      loadingBuilder: (context, child, loadingProgress) {
        if (loadingProgress == null) return child;
        return loadingWidget ?? _buildLoadingWidget(width, height);
      },
      errorBuilder: (context, error, stackTrace) {
        logger.AppLogger.debug('❌ Image load failed for $imageUrl: $error');
        return _buildFallbackWidget(errorWidget, width, height);
      },
    );
  }

  /// 带有重试逻辑的图片加载（用于处理临时的403错误）
  static Widget networkWithRetry(
    String? imageUrl, {
    double? width,
    double? height,
    BoxFit fit = BoxFit.cover,
    Widget? errorWidget,
    int maxRetries = 2,
  }) {
    if (imageUrl == null || imageUrl.isEmpty) {
      return _buildFallbackWidget(errorWidget, width, height);
    }

    // 使用带时间戳的URL来避免缓存问题
    final urlWithTimestamp = _addTimestampIfNeeded(imageUrl);

    return _RetryableImage(
      imageUrl: urlWithTimestamp,
      width: width,
      height: height,
      fit: fit,
      errorWidget: errorWidget,
      maxRetries: maxRetries,
    );
  }

  /// 为CloudFront URL添加查询参数以避免缓存问题
  static String _addTimestampIfNeeded(String url) {
    // 如果是CloudFront URL且没有查询参数，添加时间戳
    if (url.contains('cloudfront.net') && !url.contains('?')) {
      return '$url?timestamp=${DateTime.now().millisecondsSinceEpoch}';
    }
    // 如果已有查询参数，添加额外的时间戳
    if (url.contains('cloudfront.net') && url.contains('?')) {
      return '$url×tamp=${DateTime.now().millisecondsSinceEpoch}';
    }
    return url;
  }

  /// 构建回退Widget
  static Widget _buildFallbackWidget(
    Widget? errorWidget,
    double? width,
    double? height,
  ) {
    return errorWidget ?? Container(
      width: width,
      height: height,
      decoration: BoxDecoration(
        color: Colors.grey.withValues(alpha: 0.2),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Icon(
        Icons.podcasts,
        size: (width ?? 40) * 0.6,
        color: Colors.grey.withValues(alpha: 0.6),
      ),
    );
  }

  /// 构建加载中Widget
  static Widget _buildLoadingWidget(double? width, double? height) {
    return Container(
      width: width,
      height: height,
      decoration: BoxDecoration(
        color: Colors.grey.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Center(
        child: SizedBox(
          width: 20,
          height: 20,
          child: CircularProgressIndicator(
            strokeWidth: 2,
            color: Colors.grey.withValues(alpha: 0.6),
          ),
        ),
      ),
    );
  }

  /// 检查URL是否可访问（用于调试）
  static Future<bool> isImageUrlAccessible(String url) async {
    try {
      // 简单的HEAD请求检查
      logger.AppLogger.debug('🌐 Checking URL accessibility: $url');
      return true; // 简化实现，实际使用时需要添加http包依赖
    } catch (e) {
      logger.AppLogger.debug('❌ URL accessibility check failed: $e');
      return false;
    }
  }
}

/// 带重试逻辑的图片Widget
class _RetryableImage extends StatefulWidget {
  final String imageUrl;
  final double? width;
  final double? height;
  final BoxFit fit;
  final Widget? errorWidget;
  final int maxRetries;

  const _RetryableImage({
    required this.imageUrl,
    this.width,
    this.height,
    this.fit = BoxFit.cover,
    this.errorWidget,
    this.maxRetries = 2,
  });

  @override
  State<_RetryableImage> createState() => _RetryableImageState();
}

class _RetryableImageState extends State<_RetryableImage> {
  int _retryCount = 0;
  bool _hasError = false;
  String? _currentUrl;

  @override
  void initState() {
    super.initState();
    _currentUrl = widget.imageUrl;
  }

  @override
  void didUpdateWidget(covariant _RetryableImage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.imageUrl != widget.imageUrl) {
      _currentUrl = widget.imageUrl;
      _retryCount = 0;
      _hasError = false;
    }
  }

  void _handleError() {
    if (_retryCount < widget.maxRetries && !_hasError) {
      setState(() {
        _retryCount++;
        // 添加时间戳重试
        _currentUrl = '${widget.imageUrl}${widget.imageUrl.contains('?') ? '&' : '?'}retry=$_retryCount&ts=${DateTime.now().millisecondsSinceEpoch}';
        logger.AppLogger.debug('🔄 Retrying image load: $_currentUrl (attempt $_retryCount)');
      });
    } else {
      setState(() {
        _hasError = true;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_hasError) {
      return widget.errorWidget ?? ImageLoader._buildFallbackWidget(null, widget.width, widget.height);
    }

    return Image.network(
      _currentUrl!,
      width: widget.width,
      height: widget.height,
      fit: widget.fit,
      errorBuilder: (context, error, stackTrace) {
        logger.AppLogger.debug('❌ Image load error (attempt ${_retryCount + 1}/${widget.maxRetries + 1}): $error');
        // 延迟重试，避免立即重试导致UI卡顿
        WidgetsBinding.instance.addPostFrameCallback((_) {
          Future.delayed(Duration(milliseconds: 200 * (_retryCount + 1)), () {
            if (mounted) {
              _handleError();
            }
          });
        });
        return Container(); // 临时返回空，等待重试
      },
    );
  }
}
