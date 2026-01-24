import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../../../../../../core/localization/app_localizations.dart';

/// ============================================
/// SpeedRuler - 倍速播放刻度尺控件
/// ============================================

/// 倍速播放刻度尺控件 / Playback speed ruler widget
///
/// 一个可复用的倍速选择器，采用刻度尺样式设计
/// A reusable speed selector with ruler-style design
class SpeedRuler extends StatefulWidget {
  /// 最小倍速值 / Minimum speed value
  final double min;

  /// 最大倍速值 / Maximum speed value
  final double max;

  /// 步长值 / Step value (e.g., 0.1)
  final double step;

  /// 主要刻度间隔 / Major tick interval (e.g., 0.5)
  final double majorStep;

  /// 当前值 / Current value
  final double value;

  /// 值变化回调 / Value change callback
  final ValueChanged<double>? onChanged;

  /// 刻度宽度 / Tick width
  final double tickWidth;

  /// 主要刻度高度 / Major tick height
  final double majorTickHeight;

  /// 次要刻度高度 / Minor tick height
  final double minorTickHeight;

  /// 指示线宽度 / Indicator line width
  final double indicatorWidth;

  const SpeedRuler({
    super.key,
    this.min = 0.5,
    this.max = 3.0,
    this.step = 0.1,
    this.majorStep = 0.5,
    required this.value,
    this.onChanged,
    this.tickWidth = 2.0,
    this.majorTickHeight = 24.0,
    this.minorTickHeight = 12.0,
    this.indicatorWidth = 4.0,
  });

  @override
  State<SpeedRuler> createState() => _SpeedRulerState();
}

class _SpeedRulerState extends State<SpeedRuler>
    with SingleTickerProviderStateMixin {
  late double _currentValue;
  late AnimationController _animationController;
  late Animation<double> _animation;

  // 上一次触发触感反馈的值 / Last value that triggered haptic feedback
  double _lastHapticValue = 0.0;

  @override
  void initState() {
    super.initState();
    _currentValue = widget.value;
    _animationController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 200),
    );
    _animation = CurvedAnimation(
      parent: _animationController,
      curve: Curves.easeOut,
    );
  }

  @override
  void didUpdateWidget(SpeedRuler oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.value != oldWidget.value) {
      _animateToValue(widget.value);
    }
  }

  @override
  void dispose() {
    _animationController.dispose();
    super.dispose();
  }

  /// 动画过渡到指定值 / Animate to a specific value
  void _animateToValue(double targetValue) {
    final startValue = _currentValue;
    _animation = Tween<double>(
      begin: startValue,
      end: targetValue,
    ).animate(CurvedAnimation(
      parent: _animationController,
      curve: Curves.easeOut,
    ));

    _animationController.reset();
    _animationController.forward();
  }

  /// 将水平位移转换为值 / Convert horizontal offset to value
  double _offsetToValue(double dx, double width) {
    // 计算总刻度数 / Calculate total number of ticks
    final totalTicks = (widget.max - widget.min) / widget.step;
    // 每个刻度的像素宽度 / Pixel width per tick
    final tickWidth = width / totalTicks;
    // 计算新的值 / Calculate new value
    final newValue = widget.min + (dx / tickWidth) * widget.step;
    return newValue;
  }

  /// 将值吸附到最近的步长 / Snap value to nearest step
  double _snapToStep(double value) {
    final snapped = (value / widget.step).round() * widget.step;
    return snapped.clamp(widget.min, widget.max);
  }

  /// 触发触感反馈 / Trigger haptic feedback
  void _triggerHapticFeedback(double value) {
    // 检查是否跨越了 0.1 的阈值 / Check if crossed 0.1 threshold
    final currentStep = (value / widget.step).round();
    final lastStep = (_lastHapticValue / widget.step).round();

    if (currentStep != lastStep) {
      HapticFeedback.selectionClick();
      _lastHapticValue = value;
    }
  }

  /// 处理拖拽更新 / Handle drag update
  void _handleDragUpdate(DragUpdateDetails details, double width) {
    if (widget.onChanged == null) return;

    // 将全局位移转换为本地偏移 / Convert global delta to local offset
    // 这里需要考虑当前值的位置 / Need to consider current value position
    final totalTicks = (widget.max - widget.min) / widget.step;
    final tickWidth = width / totalTicks;
    final deltaValue = (details.delta.dx / tickWidth) * widget.step;
    final newValue = _currentValue + deltaValue;

    // 限制范围 / Clamp to range
    final clampedValue = newValue.clamp(widget.min, widget.max);

    // 触发触感反馈 / Trigger haptic feedback
    _triggerHapticFeedback(clampedValue);

    setState(() {
      _currentValue = clampedValue;
    });

    widget.onChanged!(clampedValue);
  }

  /// 处理拖拽结束 / Handle drag end
  void _handleDragEnd(DragEndDetails details) {
    if (widget.onChanged == null) return;

    // 吸附到最近的步长 / Snap to nearest step
    final snappedValue = _snapToStep(_currentValue);

    _animateToValue(snappedValue);

    setState(() {
      _currentValue = snappedValue;
    });

    widget.onChanged!(snappedValue);
  }

  /// 处理点击 / Handle tap
  void _handleTap(TapDownDetails details, double width) {
    if (widget.onChanged == null) return;

    // 从点击位置计算值 / Calculate value from tap position
    final clickedValue = _offsetToValue(details.localPosition.dx, width);
    final snappedValue = _snapToStep(clickedValue);

    _animateToValue(snappedValue);

    setState(() {
      _currentValue = snappedValue;
    });

    widget.onChanged!(snappedValue);
    HapticFeedback.selectionClick();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return AnimatedBuilder(
      animation: _animation,
      builder: (context, child) {
        final animatedValue = _animation.value;

        return LayoutBuilder(
          builder: (context, constraints) {
            final width = constraints.maxWidth;

            return GestureDetector(
              onPanUpdate: (details) => _handleDragUpdate(details, width),
              onPanEnd: _handleDragEnd,
              onTapDown: (details) => _handleTap(details, width),
              behavior: HitTestBehavior.opaque,
              child: CustomPaint(
                size: Size(width, 90),
                painter: _SpeedRulerPainter(
                  value: animatedValue,
                  min: widget.min,
                  max: widget.max,
                  step: widget.step,
                  majorStep: widget.majorStep,
                  tickWidth: widget.tickWidth,
                  majorTickHeight: widget.majorTickHeight,
                  minorTickHeight: widget.minorTickHeight,
                  indicatorWidth: widget.indicatorWidth,
                  primaryColor: colorScheme.primary,
                  onSurfaceVariantColor: colorScheme.onSurfaceVariant,
                  outlineColor: colorScheme.outline,
                ),
              ),
            );
          },
        );
      },
    );
  }
}

/// CustomPainter for drawing the speed ruler / 用于绘制倍速刻度尺的 CustomPainter
class _SpeedRulerPainter extends CustomPainter {
  final double value;
  final double min;
  final double max;
  final double step;
  final double majorStep;
  final double tickWidth;
  final double majorTickHeight;
  final double minorTickHeight;
  final double indicatorWidth;
  final Color primaryColor;
  final Color onSurfaceVariantColor;
  final Color outlineColor;

  _SpeedRulerPainter({
    required this.value,
    required this.min,
    required this.max,
    required this.step,
    required this.majorStep,
    required this.tickWidth,
    required this.majorTickHeight,
    required this.minorTickHeight,
    required this.indicatorWidth,
    required this.primaryColor,
    required this.onSurfaceVariantColor,
    required this.outlineColor,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final width = size.width;
    final height = size.height;

    // 计算总刻度数 / Calculate total number of ticks
    final totalTicks = ((max - min) / step).round();
    // 每个刻度的像素宽度 / Pixel width per tick
    final tickSpacing = width / totalTicks;

    // 刻度基线 Y 坐标 / Y coordinate of tick baseline (居中)
    final baselineY = height / 2;

    // 主要刻度线高度 / Major tick height (更长)
    final majorTickHeight = 28.0;
    // 次要刻度线高度 / Minor tick height (更短)
    final minorTickHeight = 14.0;

    // 文本基线 Y 坐标 / Y coordinate of text baseline (刻度线上方)
    final textBaselineY = baselineY - majorTickHeight - 12;
    // 指示线上方的当前值 Y 坐标 / Current value above indicator
    final currentValueY = baselineY - majorTickHeight - 24;

    // 绘制刻度和标签 / Draw ticks and labels
    for (int i = 0; i <= totalTicks; i++) {
      final tickValue = min + (i * step);
      final x = i * tickSpacing;

      // 判断是否为主要刻度 / Check if this is a major tick
      final isMajorTick =
          (tickValue % majorStep).abs() < 0.001 || tickValue == min || tickValue == max;

      // 选择刻度颜色 / Select tick color
      // 主刻度更明显，次刻度更淡 / Major ticks more visible, minor ticks lighter
      final tickColor = isMajorTick
          ? onSurfaceVariantColor.withValues(alpha: 0.5)  // 主刻度较明显
          : outlineColor.withValues(alpha: 0.25);         // 次刻度更淡

      // 选择刻度高度 / Select tick height
      final tickHeight = isMajorTick ? majorTickHeight : minorTickHeight;

      // 绘制刻度线 / Draw tick line
      final tickPaint = Paint()
        ..color = tickColor
        ..strokeWidth = isMajorTick ? 2.0 : 1.5  // 主刻度稍粗
        ..strokeCap = StrokeCap.round;

      // 刻度线从基线向上延伸 / Ticks extend upward from baseline
      final tickStartY = baselineY;
      final tickEndY = baselineY - tickHeight;
      canvas.drawLine(
        Offset(x, tickStartY),
        Offset(x, tickEndY),
        tickPaint,
      );

      // 绘制主要刻度的标签 / Draw labels for major ticks
      if (isMajorTick) {
        final textPainter = TextPainter(
          text: TextSpan(
            text: tickValue == tickValue.truncateToDouble()
                ? tickValue.toInt().toString()  // 整数不显示小数点 (1.0 -> 1)
                : tickValue.toStringAsFixed(1),  // 一位小数 (0.5, 1.5, 2.5)
            style: TextStyle(
              color: onSurfaceVariantColor.withValues(alpha: 0.7),
              fontSize: 13,
              fontWeight: FontWeight.w500,
            ),
          ),
          textDirection: ui.TextDirection.ltr,
        );
        textPainter.layout();
        // 文本居中对齐刻度 / Center text on tick
        textPainter.paint(
          canvas,
          Offset(x - textPainter.width / 2, textBaselineY),
        );
      }
    }

    // 绘制选中指示线 / Draw selected indicator line
    // 计算当前值的 X 坐标 / Calculate X coordinate of current value
    final valueOffset = ((value - min) / step) * tickSpacing;
    final indicatorX = valueOffset;

    // 绘制指示线 / Draw indicator line (贯穿整个刻度区域)
    final indicatorPaint = Paint()
      ..color = primaryColor
      ..strokeWidth = 3.0
      ..strokeCap = StrokeCap.round;

    // 指示线从刻度线下方延伸到上方 / Indicator extends through the ticks
    final indicatorStartY = baselineY - majorTickHeight - 8;
    final indicatorEndY = baselineY + majorTickHeight - 4;
    canvas.drawLine(
      Offset(indicatorX, indicatorStartY),
      Offset(indicatorX, indicatorEndY),
      indicatorPaint,
    );

    // 绘制当前值标签（在指示线正上方）/ Draw current value label (above indicator)
    final currentValueText = value == value.truncateToDouble()
        ? '${value.toInt()}.0x'  // 1 -> 1.0x
        : '${value.toStringAsFixed(1)}x';
    final valueTextPainter = TextPainter(
      text: TextSpan(
        text: currentValueText,
        style: TextStyle(
          color: primaryColor,
          fontSize: 18,
          fontWeight: FontWeight.bold,
        ),
      ),
      textDirection: ui.TextDirection.ltr,
    );
    valueTextPainter.layout();
    // 标签位于指示线正上方 / Label centered above indicator line
    valueTextPainter.paint(
      canvas,
      Offset(indicatorX - valueTextPainter.width / 2, currentValueY),
    );
  }

  @override
  bool shouldRepaint(_SpeedRulerPainter oldDelegate) {
    return oldDelegate.value != value ||
        oldDelegate.min != min ||
        oldDelegate.max != max;
  }
}

/// ============================================
/// SpeedRulerSheet - 倍速播放底部弹窗
/// ============================================

/// 倍速播放底部弹窗 / Playback speed bottom sheet
///
/// 展示倍速选择器的底部弹窗，包含标题、当前值和刻度尺
/// Bottom sheet displaying speed selector with title, current value, and ruler
class SpeedRulerSheet extends StatefulWidget {
  /// 弹窗标题 / Sheet title
  final String? title;

  /// 初始值 / Initial value
  final double initialValue;

  /// 值变化回调 / Value change callback
  final ValueChanged<double>? onSpeedChanged;

  /// 最小倍速 / Minimum speed
  final double min;

  /// 最大倍速 / Maximum speed
  final double max;

  /// 步长 / Step value
  final double step;

  /// 主要刻度间隔 / Major tick interval
  final double majorStep;

  const SpeedRulerSheet({
    super.key,
    this.title,
    this.initialValue = 1.5,
    this.onSpeedChanged,
    this.min = 0.5,
    this.max = 3.0,
    this.step = 0.1,
    this.majorStep = 0.5,
  });

  /// 显示倍速选择底部弹窗 / Show speed selection bottom sheet
  ///
  /// 返回选定的倍速值 / Returns the selected speed value
  static Future<double?> show({
    required BuildContext context,
    String? title,
    double initialValue = 1.5,
    ValueChanged<double>? onSpeedChanged,
    double min = 0.5,
    double max = 3.0,
    double step = 0.1,
    double majorStep = 0.5,
  }) {
    return showModalBottomSheet<double>(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (context) => SpeedRulerSheet(
        title: title,
        initialValue: initialValue,
        onSpeedChanged: onSpeedChanged,
        min: min,
        max: max,
        step: step,
        majorStep: majorStep,
      ),
    );
  }

  @override
  State<SpeedRulerSheet> createState() => _SpeedRulerSheetState();
}

class _SpeedRulerSheetState extends State<SpeedRulerSheet> {
  late double _currentValue;

  @override
  void initState() {
    super.initState();
    _currentValue = widget.initialValue;
  }

  @override
  void didUpdateWidget(SpeedRulerSheet oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.initialValue != oldWidget.initialValue) {
      _currentValue = widget.initialValue;
    }
  }

  void _handleValueChanged(double value) {
    setState(() {
      _currentValue = value;
    });
    widget.onSpeedChanged?.call(value);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final textTheme = theme.textTheme;

    return Container(
      decoration: BoxDecoration(
        color: colorScheme.surface,
        borderRadius: const BorderRadius.vertical(
          top: Radius.circular(28),
        ),
      ),
      padding: EdgeInsets.only(
        bottom: MediaQuery.viewInsetsOf(context).bottom,
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // 顶部拖拽指示器 / Top drag indicator
          Container(
            margin: const EdgeInsets.only(top: 12),
            width: 40,
            height: 4,
            decoration: BoxDecoration(
              color: colorScheme.onSurfaceVariant.withValues(alpha: 0.4),
              borderRadius: BorderRadius.circular(2),
            ),
          ),

          // 头部：标题和当前值 / Header: title and current value
          Padding(
            padding: const EdgeInsets.symmetric(
              horizontal: 24,
              vertical: 18,
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                // 标题 / Title
                Text(
                  widget.title ??
                      AppLocalizations.of(context)!.podcast_speed_title,
                  style: textTheme.titleLarge?.copyWith(
                    fontWeight: FontWeight.w500,
                  ),
                ),
                // 当前值 / Current value
                Text(
                  '${_currentValue.toStringAsFixed(1)}x',
                  style: textTheme.titleLarge?.copyWith(
                    color: colorScheme.primary,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
          ),

          // 分隔线 / Divider
          Divider(
            height: 1,
            thickness: 1,
            color: colorScheme.outlineVariant.withValues(alpha: 0.5),
          ),

          // 刻度尺 / Ruler
          Padding(
            padding: const EdgeInsets.symmetric(
              horizontal: 24,
              vertical: 24,
            ),
            child: SizedBox(
              height: 90,
              child: SpeedRuler(
                min: widget.min,
                max: widget.max,
                step: widget.step,
                majorStep: widget.majorStep,
                value: _currentValue,
                onChanged: _handleValueChanged,
              ),
            ),
          ),

          // 底部安全区域 / Bottom safe area
          SizedBox(height: MediaQuery.viewPaddingOf(context).bottom),
        ],
      ),
    );
  }
}

/// ============================================
/// SpeedRulerDemoPage - 演示页面
/// ============================================

/// 倍速播放控件演示页面 / Speed ruler widget demo page
///
/// 展示如何使用 SpeedRulerSheet 组件
/// Demonstrates how to use the SpeedRulerSheet component
class SpeedRulerDemoPage extends StatefulWidget {
  const SpeedRulerDemoPage({super.key});

  @override
  State<SpeedRulerDemoPage> createState() => _SpeedRulerDemoPageState();
}

class _SpeedRulerDemoPageState extends State<SpeedRulerDemoPage> {
  double _currentSpeed = 1.5;
  String _lastAction = '';

  void _showSpeedRulerSheet() async {
    final l10n = AppLocalizations.of(context)!;
    setState(() {
      _lastAction = l10n.podcast_speed_select;
    });

    final selectedSpeed = await SpeedRulerSheet.show(
      context: context,
      initialValue: _currentSpeed,
      min: 0.5,
      max: 3.0,
      step: 0.1,
      majorStep: 0.5,
      onSpeedChanged: (speed) {
        // 实时更新当前速度 / Update current speed in real-time
        setState(() {
          _currentSpeed = speed;
          _lastAction =
              '${l10n.podcast_speed_current_speed}: ${speed.toStringAsFixed(1)}x';
        });
      },
    );

    if (selectedSpeed != null) {
      setState(() {
        _currentSpeed = selectedSpeed;
        _lastAction =
            '${l10n.podcast_speed_select}: ${selectedSpeed.toStringAsFixed(1)}x';
      });
    } else {
      setState(() {
        _lastAction = l10n.cancel;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final l10n = AppLocalizations.of(context)!;

    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.podcast_speed_title),
        backgroundColor: colorScheme.surface,
        elevation: 0,
      ),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              // 当前倍速显示 / Current speed display
              Container(
                padding: const EdgeInsets.all(32),
                decoration: BoxDecoration(
                  color: colorScheme.primaryContainer,
                  borderRadius: BorderRadius.circular(16),
                ),
                child: Column(
                  children: [
                    Text(
                      l10n.podcast_speed_current_speed,
                      style: theme.textTheme.titleMedium?.copyWith(
                        color: colorScheme.onPrimaryContainer,
                      ),
                    ),
                    const SizedBox(height: 16),
                    Text(
                      '${_currentSpeed.toStringAsFixed(1)}x',
                      style: theme.textTheme.displayLarge?.copyWith(
                        color: colorScheme.primary,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 32),

              // 操作说明 / Action description
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 24,
                  vertical: 16,
                ),
                decoration: BoxDecoration(
                  color: colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Row(
                  children: [
                    Icon(
                      Icons.info_outline,
                      color: colorScheme.primary,
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        _lastAction.isEmpty
                            ? l10n.podcast_speed_select
                            : _lastAction,
                        style: theme.textTheme.bodyMedium,
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 48),

              // 打开倍速选择器按钮 / Button to open speed selector
              FilledButton.tonalIcon(
                onPressed: _showSpeedRulerSheet,
                icon: const Icon(Icons.speed),
                label: Text(l10n.podcast_speed_select),
                style: FilledButton.styleFrom(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 32,
                    vertical: 20,
                  ),
                  textStyle: theme.textTheme.titleMedium,
                ),
              ),

              const SizedBox(height: 24),

              // 功能说明 / Feature description
              Text(
                '${l10n.podcast_speed_feature_1}\n'
                '${l10n.podcast_speed_feature_2}\n'
                '${l10n.podcast_speed_feature_3}\n'
                '${l10n.podcast_speed_feature_4}\n'
                '${l10n.podcast_speed_feature_5}',
                textAlign: TextAlign.center,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: colorScheme.onSurfaceVariant,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
