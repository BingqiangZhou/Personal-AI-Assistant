import 'package:flutter/material.dart';

/// Represents the user's sleep timer selection.
class SleepTimerSelection {
  /// Duration-based timer (null if after-episode mode).
  final Duration? duration;

  /// If true, stop after the current episode ends.
  final bool afterEpisode;

  /// If true, cancel the current timer.
  final bool cancel;

  const SleepTimerSelection({
    this.duration,
    this.afterEpisode = false,
    this.cancel = false,
  });

  const SleepTimerSelection.afterEpisode()
      : duration = null,
        afterEpisode = true,
        cancel = false;

  const SleepTimerSelection.cancel()
      : duration = null,
        afterEpisode = false,
        cancel = true;
}

/// Preset durations for the sleep timer.
const _kSleepTimerPresets = [
  Duration(minutes: 5),
  Duration(minutes: 10),
  Duration(minutes: 15),
  Duration(minutes: 30),
  Duration(minutes: 45),
  Duration(minutes: 60),
  Duration(minutes: 90),
];

String _formatPresetDuration(Duration d) {
  if (d.inMinutes >= 60) {
    final hours = d.inHours;
    final mins = d.inMinutes.remainder(60);
    return mins > 0 ? '$hours小时${mins}分钟' : '$hours小时';
  }
  return '${d.inMinutes}分钟';
}

/// Shows a bottom sheet for selecting a sleep timer option.
Future<SleepTimerSelection?> showSleepTimerSelectorSheet({
  required BuildContext context,
  required bool isTimerActive,
}) {
  return showModalBottomSheet<SleepTimerSelection>(
    context: context,
    showDragHandle: true,
    builder: (context) {
      final theme = Theme.of(context);

      return SafeArea(
        child: SingleChildScrollView(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  '睡眠定时',
                  style: theme.textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  '设置定时后，播放将在指定时间自动暂停',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
                const SizedBox(height: 16),
                // Duration presets
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: _kSleepTimerPresets.map((preset) {
                    return ActionChip(
                      label: Text(_formatPresetDuration(preset)),
                      onPressed: () {
                        Navigator.of(context).pop(
                          SleepTimerSelection(duration: preset),
                        );
                      },
                    );
                  }).toList(),
                ),
                const SizedBox(height: 12),
                const Divider(),
                // After current episode
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: Icon(
                    Icons.stop_circle_outlined,
                    color: theme.colorScheme.primary,
                  ),
                  title: const Text('播放完本集后停止'),
                  onTap: () {
                    Navigator.of(context).pop(
                      const SleepTimerSelection.afterEpisode(),
                    );
                  },
                ),
                // Cancel timer (only when active)
                if (isTimerActive) ...[
                  const Divider(),
                  ListTile(
                    contentPadding: EdgeInsets.zero,
                    leading: Icon(
                      Icons.timer_off,
                      color: theme.colorScheme.error,
                    ),
                    title: Text(
                      '取消定时',
                      style: TextStyle(color: theme.colorScheme.error),
                    ),
                    onTap: () {
                      Navigator.of(context).pop(
                        const SleepTimerSelection.cancel(),
                      );
                    },
                  ),
                ],
              ],
            ),
          ),
        ),
      );
    },
  );
}
