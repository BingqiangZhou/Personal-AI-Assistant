import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// ============================================
/// SpeedRollerPicker - 滚筒样式倍速选择器
/// ============================================

/// 滚筒样式倍速选择器 / Roller-style speed picker
///
/// 类似 iOS picker 的滚轮选择效果，从按钮位置向上弹出
class SpeedRollerPicker extends StatefulWidget {
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

  /// 滚筒高度 / Roller height
  final double height;

  /// 每项高度 / Item height
  final double itemHeight;

  const SpeedRollerPicker({
    super.key,
    this.min = 0.5,
    this.max = 3.0,
    this.step = 0.1,
    this.majorStep = 0.5,
    required this.value,
    this.onChanged,
    this.height = 200,
    this.itemHeight = 40,
  });

  @override
  State<SpeedRollerPicker> createState() => _SpeedRollerPickerState();
}

class _SpeedRollerPickerState extends State<SpeedRollerPicker> {
  late ScrollController _scrollController;
  late int _currentIndex;
  bool _isScrolling = false;

  @override
  void initState() {
    super.initState();
    _currentIndex = _valueToIndex(widget.value);
    // ListView 有 padding.top = (height/2 - itemHeight/2)
    // 当 scrollOffset = index * itemHeight 时，第 index 个 item 会居中显示
    _scrollController = ScrollController(
      initialScrollOffset: _currentIndex * widget.itemHeight,
    );
    _scrollController.addListener(_onScroll);
  }

  @override
  void didUpdateWidget(SpeedRollerPicker oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.value != oldWidget.value) {
      final newIndex = _valueToIndex(widget.value);
      if (newIndex != _currentIndex) {
        _currentIndex = newIndex;
        _scrollToIndex(_currentIndex);
      }
    }
  }

  @override
  void dispose() {
    _scrollController.removeListener(_onScroll);
    _scrollController.dispose();
    super.dispose();
  }

  int _valueToIndex(double value) {
    return ((value - widget.min) / widget.step).round();
  }

  double _indexToValue(int index) {
    return widget.min + (index * widget.step);
  }

  void _onScroll() {
    if (!_isScrolling) {
      setState(() {
        _isScrolling = true;
      });
    }

    // 由于 ListView 有 padding，scrollOffset = index * itemHeight 时，该 index 的 item 居中
    final newIndex = (_scrollController.offset / widget.itemHeight).round();

    if (newIndex != _currentIndex) {
      _currentIndex = newIndex;
      HapticFeedback.selectionClick();
      widget.onChanged?.call(_indexToValue(_currentIndex));
    }
  }

  void _scrollToIndex(int index) {
    // scrollOffset = index * itemHeight 会让该 item 居中显示
    final targetOffset = index * widget.itemHeight;
    _scrollController.animateTo(
      targetOffset.clamp(0.0, _scrollController.position.maxScrollExtent),
      duration: const Duration(milliseconds: 300),
      curve: Curves.easeOut,
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    // 计算总项数
    final totalItems = ((widget.max - widget.min) / widget.step).round() + 1;

    return SizedBox(
      height: widget.height,
      child: Stack(
        children: [
          // 背景渐变（上下边缘变暗）
          Container(
            height: widget.height,
            decoration: BoxDecoration(
              gradient: LinearGradient(
                begin: Alignment.topCenter,
                end: Alignment.bottomCenter,
                colors: [
                  colorScheme.surface.withValues(alpha: 0.95),
                  colorScheme.surface.withValues(alpha: 0.5),
                  colorScheme.surface.withValues(alpha: 0.5),
                  colorScheme.surface.withValues(alpha: 0.95),
                ],
                stops: const [0.0, 0.2, 0.8, 1.0],
              ),
            ),
          ),

          // 选中指示器（中间横线）
          Center(
            child: Container(
              height: widget.itemHeight,
              decoration: BoxDecoration(
                border: Border(
                  top: BorderSide(
                    color: colorScheme.primary.withValues(alpha: 0.3),
                    width: 1,
                  ),
                  bottom: BorderSide(
                    color: colorScheme.primary.withValues(alpha: 0.3),
                    width: 1,
                  ),
                ),
              ),
            ),
          ),

          // 滚筒列表
          ListView.builder(
            controller: _scrollController,
            physics: const ClampingScrollPhysics(),
            // 添加上下内边距，让首尾项也能滚动到中心位置
            padding: EdgeInsets.symmetric(vertical: (widget.height / 2) - (widget.itemHeight / 2)),
            itemCount: totalItems,
            itemBuilder: (context, index) {
              final rawValue = _indexToValue(index);
              // 修正浮点数精度问题：四舍五入到一位小数
              final value = (rawValue * 10).roundToDouble() / 10;
              final isMajorTick = (value % widget.majorStep).abs() < 0.001 ||
                  value == widget.min ||
                  value == widget.max;
              final isSelected = index == _currentIndex;

              return SizedBox(
                height: widget.itemHeight,
                child: Center(
                  child: Text(
                    // 显示所有数值，主要刻度更大更粗
                    value == value.truncateToDouble()
                        ? '${value.toInt()}.0x'
                        : '${value.toStringAsFixed(1)}x',
                    style: TextStyle(
                      fontSize: isSelected ? 24 : (isMajorTick ? 18 : 14),
                      fontWeight: isSelected ? FontWeight.bold : (isMajorTick ? FontWeight.w500 : FontWeight.normal),
                      color: isSelected
                          ? colorScheme.primary
                          : colorScheme.onSurfaceVariant.withValues(alpha: isMajorTick ? 0.8 : 0.4),
                    ),
                  ),
                ),
              );
            },
          ),
        ],
      ),
    );
  }
}

/// ============================================
/// SpeedPickerPopup - 从按钮位置向上弹出的选择器
/// ============================================

/// 倍速选择弹出窗口 / Speed selection popup
///
/// 从按钮位置向上展开的弹窗，包含滚筒选择器
class SpeedPickerPopup extends StatefulWidget {
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

  const SpeedPickerPopup({
    super.key,
    this.initialValue = 1.5,
    this.onSpeedChanged,
    this.min = 0.5,
    this.max = 3.0,
    this.step = 0.1,
    this.majorStep = 0.5,
  });

  /// 显示倍速选择弹窗 / Show speed selection popup
  ///
  /// 从指定按钮位置向上弹出
  static Future<double?> show({
    required BuildContext context,
    required GlobalKey buttonKey,
    double initialValue = 1.5,
    ValueChanged<double>? onSpeedChanged,
    double min = 0.5,
    double max = 3.0,
    double step = 0.1,
    double majorStep = 0.5,
  }) {
    return showDialog<double>(
      context: context,
      barrierColor: Colors.black.withValues(alpha: 0.3),
      builder: (context) => _SpeedPickerPopupDialog(
        buttonKey: buttonKey,
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
  State<SpeedPickerPopup> createState() => _SpeedPickerPopupState();
}

class _SpeedPickerPopupState extends State<SpeedPickerPopup> {
  @override
  Widget build(BuildContext context) {
    // 这是一个内部使用的类，实际使用通过 SpeedPickerPopup.show()
    return const SizedBox.shrink();
  }
}

/// 弹窗内容 Dialog
class _SpeedPickerPopupDialog extends StatelessWidget {
  final GlobalKey buttonKey;
  final double initialValue;
  final ValueChanged<double>? onSpeedChanged;
  final double min;
  final double max;
  final double step;
  final double majorStep;

  const _SpeedPickerPopupDialog({
    required this.buttonKey,
    required this.initialValue,
    required this.onSpeedChanged,
    required this.min,
    required this.max,
    required this.step,
    required this.majorStep,
  });

  @override
  Widget build(BuildContext context) {
    // 获取按钮位置和大小
    final RenderBox? renderBox =
        buttonKey.currentContext?.findRenderObject() as RenderBox?;
    if (renderBox == null) {
      return const SizedBox.shrink();
    }

    final buttonPosition = renderBox.localToGlobal(Offset.zero);
    final buttonSize = renderBox.size;
    final screenWidth = MediaQuery.of(context).size.width;

    // 计算弹窗位置（从按钮向上展开）
    final popupWidth = 280.0;
    final popupMargin = 16.0;

    // 弹窗在按钮上方，水平居中对齐按钮
    final left = buttonPosition.dx + (buttonSize.width / 2) - (popupWidth / 2);
    final right = screenWidth - left - popupWidth;

    // 确保不超出屏幕边界
    final adjustedLeft = left < popupMargin
        ? popupMargin
        : (right < popupMargin ? screenWidth - popupWidth - popupMargin : left);

    final bottom = screenHeight - buttonPosition.dy + popupMargin;

    return Material(
      color: Colors.transparent,
      child: Stack(
        children: [
          // 点击背景关闭
          Positioned.fill(
            child: GestureDetector(
              onTap: () => Navigator.of(context).pop(),
              behavior: HitTestBehavior.opaque,
            ),
          ),

          // 弹窗内容
          Positioned(
            left: adjustedLeft,
            bottom: bottom,
            child: _SpeedPickerContent(
              initialValue: initialValue,
              onSpeedChanged: onSpeedChanged,
              min: min,
              max: max,
              step: step,
              majorStep: majorStep,
              onClose: () => Navigator.of(context).pop(),
            ),
          ),
        ],
      ),
    );
  }

  double get screenHeight =>
      WidgetsBinding.instance.platformDispatcher.views.first.physicalSize.height /
      WidgetsBinding.instance.platformDispatcher.views.first.devicePixelRatio;
}

/// 弹窗主体内容
class _SpeedPickerContent extends StatefulWidget {
  final double initialValue;
  final ValueChanged<double>? onSpeedChanged;
  final double min;
  final double max;
  final double step;
  final double majorStep;
  final VoidCallback onClose;

  const _SpeedPickerContent({
    required this.initialValue,
    required this.onSpeedChanged,
    required this.min,
    required this.max,
    required this.step,
    required this.majorStep,
    required this.onClose,
  });

  @override
  State<_SpeedPickerContent> createState() => _SpeedPickerContentState();
}

class _SpeedPickerContentState extends State<_SpeedPickerContent> {
  late double _currentValue;

  @override
  void initState() {
    super.initState();
    _currentValue = widget.initialValue;
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final textTheme = theme.textTheme;

    return Container(
      width: 280,
      decoration: BoxDecoration(
        color: colorScheme.surface,
        borderRadius: BorderRadius.circular(16),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.3),
            blurRadius: 20,
            offset: const Offset(0, 8),
          ),
        ],
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // 标题栏
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
            decoration: BoxDecoration(
              color: colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
              borderRadius: const BorderRadius.vertical(
                top: Radius.circular(16),
              ),
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  '倍速播放',
                  style: textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w600,
                  ),
                ),
                // 当前值显示
                Text(
                  '${_currentValue.toStringAsFixed(1)}x',
                  style: textTheme.titleMedium?.copyWith(
                    color: colorScheme.primary,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
          ),

          // 滚筒选择器
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
            child: SizedBox(
              height: 200,
              child: SpeedRollerPicker(
                min: widget.min,
                max: widget.max,
                step: widget.step,
                majorStep: widget.majorStep,
                value: _currentValue,
                onChanged: (value) {
                  setState(() {
                    _currentValue = value;
                  });
                  widget.onSpeedChanged?.call(value);
                },
              ),
            ),
          ),

          // 关闭按钮
          Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
            decoration: BoxDecoration(
              border: Border(
                top: BorderSide(
                  color: colorScheme.outlineVariant.withValues(alpha: 0.5),
                  width: 1,
                ),
              ),
            ),
            child: TextButton(
              onPressed: widget.onClose,
              child: const Text('完成'),
            ),
          ),
        ],
      ),
    );
  }
}
