import 'package:flutter/material.dart';
import 'package:shimmer/shimmer.dart';
import '../../core/theme/app_theme.dart';

class LoadingWidget extends StatelessWidget {
  final double? size;
  final Color? color;

  const LoadingWidget({
    super.key,
    this.size,
    this.color,
  });

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: size ?? 24,
      height: size ?? 24,
      child: CircularProgressIndicator(
        strokeWidth: 2.5,
        valueColor: AlwaysStoppedAnimation<Color>(
          color ?? AppTheme.primaryColor,
        ),
      ),
    );
  }
}

class LoadingOverlay extends StatelessWidget {
  final Widget child;
  final bool isLoading;
  final String? loadingText;

  const LoadingOverlay({
    super.key,
    required this.child,
    required this.isLoading,
    this.loadingText,
  });

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        child,
        if (isLoading)
          Container(
            color: Colors.black.withOpacity(0.5),
            child: Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const LoadingWidget(size: 48),
                  if (loadingText != null) ...[
                    const SizedBox(height: 16),
                    Text(
                      loadingText!,
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 16,
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
      ],
    );
  }
}

class ShimmerLoading extends StatelessWidget {
  final Widget child;
  final Color? baseColor;
  final Color? highlightColor;

  const ShimmerLoading({
    super.key,
    required this.child,
    this.baseColor,
    this.highlightColor,
  });

  @override
  Widget build(BuildContext context) {
    return Shimmer(
      gradient: LinearGradient(
        colors: [
          baseColor ?? Colors.grey[300]!,
          highlightColor ?? Colors.grey[100]!,
          baseColor ?? Colors.grey[300]!,
        ],
        stops: const [0.0, 0.5, 1.0],
        begin: const Alignment(-1.0, -0.3),
        end: const Alignment(1.0, 0.3),
      ),
      child: child,
    );
  }
}