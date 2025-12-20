import 'package:flutter/material.dart';

class PlatformBadge extends StatelessWidget {
  final String? platform;

  const PlatformBadge({
    super.key,
    this.platform,
  });

  @override
  Widget build(BuildContext context) {
    if (platform == null || platform!.isEmpty || platform == 'generic') {
      return const SizedBox.shrink();
    }

    final config = _getPlatformConfig(platform!);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: config.color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(
          color: config.color.withValues(alpha: 0.3),
          width: 1,
        ),
      ),
      child: Text(
        config.label,
        style: TextStyle(
          fontSize: 10,
          color: config.color,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }

  _PlatformConfig _getPlatformConfig(String platform) {
    switch (platform.toLowerCase()) {
      case 'xiaoyuzhou':
        return _PlatformConfig(
          label: '小宇宙',
          color: const Color(0xFFFF6B35),
        );
      case 'ximalaya':
        return _PlatformConfig(
          label: '喜马拉雅',
          color: const Color(0xFFE53935),
        );
      default:
        return _PlatformConfig(
          label: platform,
          color: const Color(0xFF757575),
        );
    }
  }
}

class _PlatformConfig {
  final String label;
  final Color color;

  _PlatformConfig({
    required this.label,
    required this.color,
  });
}
