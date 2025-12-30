import 'package:flutter/material.dart';

/// 播客图片加载组件，专门处理CloudFront 403等CDN访问问题
class PodcastImageWidget extends StatefulWidget {
  final String? imageUrl;
  final String? fallbackImageUrl;
  final double width;
  final double height;
  final BoxFit fit;
  final Color? iconColor;
  final double? iconSize;

  const PodcastImageWidget({
    super.key,
    required this.imageUrl,
    this.fallbackImageUrl,
    required this.width,
    required this.height,
    this.fit = BoxFit.cover,
    this.iconColor,
    this.iconSize,
  });

  @override
  State<PodcastImageWidget> createState() => _PodcastImageWidgetState();
}

class _PodcastImageWidgetState extends State<PodcastImageWidget> {
  int _retryCount = 0;
  bool _useFallback = false;
  String? _currentImageUrl;

  @override
  void initState() {
    super.initState();
    // 如果 imageUrl 为 null 或空，自动使用 fallbackImageUrl
    if (widget.imageUrl == null || widget.imageUrl!.isEmpty) {
      _currentImageUrl = widget.fallbackImageUrl;
      _useFallback = widget.fallbackImageUrl != null;
    } else {
      _currentImageUrl = widget.imageUrl;
    }
  }

  @override
  void didUpdateWidget(covariant PodcastImageWidget oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.imageUrl != widget.imageUrl || oldWidget.fallbackImageUrl != widget.fallbackImageUrl) {
      // 如果 imageUrl 为 null 或空，自动使用 fallbackImageUrl
      if (widget.imageUrl == null || widget.imageUrl!.isEmpty) {
        _currentImageUrl = widget.fallbackImageUrl;
        _useFallback = widget.fallbackImageUrl != null;
      } else {
        _currentImageUrl = widget.imageUrl;
        _useFallback = false;
      }
      _retryCount = 0;
    }
  }

  void _handleImageError() {
    debugPrint('❌ Failed to load image: ${widget.imageUrl} (attempt ${_retryCount + 1})');

    // 如果当前使用的是 fallbackImageUrl 且已经出错，直接显示图标
    if (_useFallback && widget.fallbackImageUrl != null && _currentImageUrl == widget.fallbackImageUrl) {
      setState(() {
        _currentImageUrl = null;
      });
      return;
    }

    if (_retryCount < 2 && !_useFallback && widget.imageUrl != null) {
      // 尝试重试，添加时间戳避免缓存
      setState(() {
        _retryCount++;
        final timestamp = DateTime.now().millisecondsSinceEpoch;
        final separator = widget.imageUrl!.contains('?') ? '&' : '?';
        _currentImageUrl = '${widget.imageUrl}$separator$timestamp';
      });
    } else if (widget.fallbackImageUrl != null && !_useFallback) {
      // 切换到回退图片
      setState(() {
        _useFallback = true;
        _currentImageUrl = widget.fallbackImageUrl;
        _retryCount = 0;
      });
    } else {
      // 最终回退到图标
      setState(() {
        _useFallback = true;
        _currentImageUrl = null;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final iconColor = widget.iconColor ?? theme.colorScheme.primary;
    final iconSize = widget.iconSize ?? (widget.width * 0.6);

    // 没有图片URL，显示图标
    if (_currentImageUrl == null || _currentImageUrl!.isEmpty) {
      return _buildIconPlaceholder(iconColor, iconSize);
    }

    return Image.network(
      _currentImageUrl!,
      width: widget.width,
      height: widget.height,
      fit: widget.fit,
      frameBuilder: (context, child, frame, wasSynchronouslyLoaded) {
        if (wasSynchronouslyLoaded) return child;
        return AnimatedOpacity(
          opacity: frame == null ? 0 : 1,
          duration: const Duration(milliseconds: 300),
          curve: Curves.easeOut,
          child: child,
        );
      },
      loadingBuilder: (context, child, loadingProgress) {
        if (loadingProgress == null) return child;
        return Container(
          width: widget.width,
          height: widget.height,
          decoration: BoxDecoration(
            color: theme.colorScheme.primary.withValues(alpha: 0.05),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Center(
            child: SizedBox(
              width: 20,
              height: 20,
              child: CircularProgressIndicator(
                strokeWidth: 2,
                value: loadingProgress.expectedTotalBytes != null
                    ? loadingProgress.cumulativeBytesLoaded /
                        loadingProgress.expectedTotalBytes!
                    : null,
                color: theme.colorScheme.primary.withValues(alpha: 0.6),
              ),
            ),
          ),
        );
      },
      errorBuilder: (context, error, stackTrace) {
        // 延迟处理错误，避免在build中立即setState
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (mounted) {
            _handleImageError();
          }
        });

        // 返回临时占位符，等待错误处理完成
        if (_retryCount > 0 || _useFallback) {
          // 正在重试或使用回退，显示加载状态
          return Container(
            width: widget.width,
            height: widget.height,
            decoration: BoxDecoration(
              color: theme.colorScheme.primary.withValues(alpha: 0.05),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(
              Icons.refresh,
              size: iconSize * 0.5,
              color: iconColor.withValues(alpha: 0.3),
            ),
          );
        }

        // 初始状态，显示透明占位
        return SizedBox(
          width: widget.width,
          height: widget.height,
        );
      },
    );
  }

  Widget _buildIconPlaceholder(Color color, double size) {
    return Container(
      width: widget.width,
      height: widget.height,
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: color.withValues(alpha: 0.3),
          width: 1,
        ),
      ),
      child: Icon(
        Icons.podcasts,
        size: size,
        color: color.withValues(alpha: 0.8),
      ),
    );
  }
}
