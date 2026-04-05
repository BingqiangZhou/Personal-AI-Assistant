import 'package:flutter/material.dart';

import 'package:personal_ai_assistant/core/theme/apple_colors.dart';
import 'package:personal_ai_assistant/core/theme/app_colors.dart';

/// ============================================================
/// Arctic Garden Design System - 页面转场动画
///
/// 转场原则：
/// - 流畅自然：有机缓动曲线
/// - 方向感：清晰的导航方向
/// - 适度：不过于花哨，保持专业
/// ============================================================

/// Page transition types for the Arctic Garden design system
enum ArcticPageTransitionType {
  fade,
  slideRight,
  slideLeft,
  slideUp,
  slideDown,
  scale,
  fadeSlide,
  aurora,
}

/// ArcticPageRoute - 北极花园页面路由
///
/// 提供流畅、一致的页面转场效果
class ArcticPageRoute<T> extends PageRouteBuilder<T> {
  ArcticPageRoute({
    required this.page,
    this.transitionType = ArcticPageTransitionType.fadeSlide,
    super.transitionDuration = const Duration(milliseconds: 400),
    super.reverseTransitionDuration = const Duration(milliseconds: 320),
    super.settings,
    super.maintainState = true,
    super.fullscreenDialog = false,
    super.opaque = true,
    super.barrierDismissible = false,
    super.barrierColor,
    super.barrierLabel,
  }) : super(
          pageBuilder: (context, animation, secondaryAnimation) => page,
        );

  final Widget page;
  final ArcticPageTransitionType transitionType;

  @override
  Widget buildTransitions(
    BuildContext context,
    Animation<double> animation,
    Animation<double> secondaryAnimation,
    Widget child,
  ) {
    // Skip animation if explicitly disabled
    if (settings.arguments is Map &&
        (settings.arguments as Map).containsKey('disableTransitions') &&
        (settings.arguments as Map)['disableTransitions'] == true) {
      return child;
    }

    return _buildTransition(animation, secondaryAnimation, child);
  }

  Widget _buildTransition(
    Animation<double> animation,
    Animation<double> secondaryAnimation,
    Widget child,
  ) {
    // Arctic Garden organic curve
    final curve = CurveTween(curve: Curves.easeOutQuart);
    final curvedAnimation = animation.drive(curve);

    switch (transitionType) {
      case ArcticPageTransitionType.fade:
        return FadeTransition(
          opacity: curvedAnimation,
          child: child,
        );

      case ArcticPageTransitionType.slideRight:
        return SlideTransition(
          position: curvedAnimation.drive(
            Tween<Offset>(
              begin: const Offset(-1.0, 0.0),
              end: Offset.zero,
            ),
          ),
          child: child,
        );

      case ArcticPageTransitionType.slideLeft:
        return SlideTransition(
          position: curvedAnimation.drive(
            Tween<Offset>(
              begin: const Offset(1.0, 0.0),
              end: Offset.zero,
            ),
          ),
          child: child,
        );

      case ArcticPageTransitionType.slideUp:
        return SlideTransition(
          position: curvedAnimation.drive(
            Tween<Offset>(
              begin: const Offset(0.0, 1.0),
              end: Offset.zero,
            ),
          ),
          child: child,
        );

      case ArcticPageTransitionType.slideDown:
        return SlideTransition(
          position: curvedAnimation.drive(
            Tween<Offset>(
              begin: const Offset(0.0, -1.0),
              end: Offset.zero,
            ),
          ),
          child: child,
        );

      case ArcticPageTransitionType.scale:
        return ScaleTransition(
          scale: curvedAnimation.drive(
            Tween<double>(begin: 0.92, end: 1.0),
          ),
          child: FadeTransition(
            opacity: curvedAnimation,
            child: child,
          ),
        );

      case ArcticPageTransitionType.fadeSlide:
        return SlideTransition(
          position: curvedAnimation.drive(
            Tween<Offset>(
              begin: const Offset(0.04, 0.0),
              end: Offset.zero,
            ),
          ),
          child: FadeTransition(
            opacity: curvedAnimation,
            child: child,
          ),
        );

      case ArcticPageTransitionType.aurora:
        return _AuroraTransition(
          animation: animation,
          child: child,
        );
    }
  }
}

/// AuroraTransition - 极光效果转场
///
/// Features a subtle cosmic aurora overlay that fades through the
/// page content, using indigo-violet with a warm amber twinkle.
class _AuroraTransition extends StatelessWidget {
  const _AuroraTransition({
    required this.animation,
    required this.child,
  });

  final Animation<double> animation;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    // Aurora overlay fades in early and fades out as content appears
    final auroraOpacity = TweenSequence<double>([
      TweenSequenceItem(
        tween: Tween(begin: 0.0, end: 0.18)
            .chain(CurveTween(curve: Curves.easeOutCubic)),
        weight: 40,
      ),
      TweenSequenceItem(
        tween: Tween(begin: 0.18, end: 0.0)
            .chain(CurveTween(curve: Curves.easeIn)),
        weight: 60,
      ),
    ]).animate(animation);

    // Content animations with cosmic deceleration
    final fadeAnimation = CurvedAnimation(
      parent: animation,
      curve: Curves.easeOutCubic,
    );

    final slideAnimation = Tween<Offset>(
      begin: const Offset(0.0, 0.03),
      end: Offset.zero,
    ).animate(CurvedAnimation(
      parent: animation,
      curve: Curves.easeOutCubic,
    ));

    final scaleAnimation = Tween<double>(begin: 0.98, end: 1.0).animate(
      CurvedAnimation(
        parent: animation,
        curve: Curves.easeOutCubic,
      ),
    );

    return Stack(
      children: [
        // Content layer
        FadeTransition(
          opacity: fadeAnimation,
          child: SlideTransition(
            position: slideAnimation,
            child: ScaleTransition(
              scale: scaleAnimation,
              child: child,
            ),
          ),
        ),
        // Aurora overlay layer — indigo-violet with warm amber twinkle
        Positioned.fill(
          child: IgnorePointer(
            child: AnimatedBuilder(
              animation: auroraOpacity,
              builder: (context, _) {
                final v = auroraOpacity.value;
                return v > 0.0
                    ? DecoratedBox(
                        decoration: BoxDecoration(
                          gradient: LinearGradient(
                            begin: Alignment.topLeft,
                            end: Alignment.bottomRight,
                            colors: [
                              AppColors.primary.withValues(alpha: v * 0.6),
                              AppColors.primaryLight.withValues(alpha: v * 0.4),
                              AppleColors.systemOrange.of(context).withValues(alpha: v * 0.15),
                            ],
                            stops: const [0.0, 0.6, 1.0],
                          ),
                        ),
                      )
                    : const SizedBox.shrink();
              },
            ),
          ),
        ),
      ],
    );
  }
}

/// ArcticTransitions - 预定义转场配置
class ArcticTransitions {
  ArcticTransitions._();

  /// Standard forward navigation (push)
  static ArcticPageTransitionType get forward => ArcticPageTransitionType.fadeSlide;

  /// Modal/bottom sheet style (push from bottom)
  static ArcticPageTransitionType get modal => ArcticPageTransitionType.slideUp;

  /// Dialog style (scale + fade)
  static ArcticPageTransitionType get dialog => ArcticPageTransitionType.scale;

  /// Simple fade (for subtle transitions)
  static ArcticPageTransitionType get subtle => ArcticPageTransitionType.fade;

  /// Quick transition for tabs/sections
  static ArcticPageTransitionType get quick => ArcticPageTransitionType.fade;

  /// Aurora effect for special pages
  static ArcticPageTransitionType get aurora => ArcticPageTransitionType.aurora;
}

