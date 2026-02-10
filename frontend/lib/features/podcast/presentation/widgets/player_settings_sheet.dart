import 'package:flutter/material.dart';
import '../constants/playback_speed_options.dart';
import '../../../../core/localization/app_localizations.dart';

// Reuse models from original files or define new ones if needed used in the sheet
// For simplicity in this refactor, I'll keep the return type simple or use a callback class
// But to match the existing patterns, let's look at what they returned.
// Speed returned: PlaybackSpeedSelection
// Timer returned: SleepTimerSelection

// We can return a result object that contains potential changes for either.
class PlayerSettingsResult {
  final PlaybackSpeedSelection? speedSelection;
  final SleepTimerSelection? timerSelection;

  PlayerSettingsResult({this.speedSelection, this.timerSelection});
}

class PlaybackSpeedSelection {
  final double speed;
  final bool applyToSubscription;

  const PlaybackSpeedSelection({
    required this.speed,
    required this.applyToSubscription,
  });
}

class SleepTimerSelection {
  final Duration? duration;
  final bool afterEpisode;
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

const _kSleepTimerPresets = [
  Duration(minutes: 5),
  Duration(minutes: 10),
  Duration(minutes: 15),
  Duration(minutes: 30),
  Duration(minutes: 45),
  Duration(minutes: 60),
  Duration(minutes: 90),
];

String _formatPresetDuration(Duration d, BuildContext context) {
  final l10n = AppLocalizations.of(context)!;
  if (d.inMinutes >= 60) {
    final hours = d.inHours;
    final mins = d.inMinutes.remainder(60);
    return mins > 0 ? l10n.player_hours_minutes(hours, mins) : l10n.player_hours(hours);
  }
  return l10n.player_minutes(d.inMinutes);
}

Future<void> showPlayerSettingsSheet({
  required BuildContext context,
  required double currentSpeed,
  required bool isTimerActive,
  String? timerRemainingLabel,
  required Function(PlaybackSpeedSelection) onSpeedChanged,
  required Function(SleepTimerSelection) onTimerChanged,
}) {
  return showModalBottomSheet<void>(
    context: context,
    showDragHandle: true,
    isScrollControlled: true, // Allow it to take more space if needed
    builder: (context) {
      return _PlayerSettingsSheetContent(
        initialSpeed: currentSpeed,
        isTimerActive: isTimerActive,
        timerRemainingLabel: timerRemainingLabel,
        onSpeedChanged: onSpeedChanged,
        onTimerChanged: onTimerChanged, // Pass callbacks directly to avoid complex return types
      );
    },
  );
}

class _PlayerSettingsSheetContent extends StatefulWidget {
  final double initialSpeed;
  final bool isTimerActive;
  final String? timerRemainingLabel;
  final Function(PlaybackSpeedSelection) onSpeedChanged;
  final Function(SleepTimerSelection) onTimerChanged;

  const _PlayerSettingsSheetContent({
    required this.initialSpeed,
    required this.isTimerActive,
    this.timerRemainingLabel,
    required this.onSpeedChanged,
    required this.onTimerChanged,
  });

  @override
  State<_PlayerSettingsSheetContent> createState() =>
      _PlayerSettingsSheetContentState();
}

class _PlayerSettingsSheetContentState
    extends State<_PlayerSettingsSheetContent> {
  late double _selectedSpeed;
  bool _applyToSubscription = false;

  @override
  void initState() {
    super.initState();
    _selectedSpeed = widget.initialSpeed;
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return SafeArea(
      child: SingleChildScrollView(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // --- Playback Speed Section ---
              Row(
                children: [
                  Icon(Icons.speed, color: theme.colorScheme.primary),
                  const SizedBox(width: 8),
                  Text(
                    AppLocalizations.of(context)!.player_playback_speed_title,
                    style: theme.textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: kPlaybackSpeedOptions.map((speed) {
                  final isSelected =
                      (_selectedSpeed - speed).abs() < 0.0001;
                  return ChoiceChip(
                    label: Text(formatPlaybackSpeed(speed)),
                    selected: isSelected,
                    onSelected: (selected) {
                      if (selected) {
                        setState(() {
                          _selectedSpeed = speed;
                        });
                        // Immediate apply for better UX or wait?
                        // The original design had an "Apply" button for speed.
                        // But for a combined sheet, immediate action might be better or specific apply buttons?
                        // Let's stick to the "Action based" approach for Chips, but since we have "Apply to subscription" checkbox, maybe we need to be careful.
                        // Actually, let's apply immediately when chip is clicked is usually expected in modern UIs,
                        // BUT the checkbox state matters.
                        // Let's trigger the callback immediately with current checkbox state.
                         widget.onSpeedChanged(PlaybackSpeedSelection(
                          speed: speed,
                          applyToSubscription: _applyToSubscription,
                        ));
                      }
                    },
                  );
                }).toList(),
              ),
              const SizedBox(height: 8),
              CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                value: _applyToSubscription,
                onChanged: (checked) {
                  setState(() {
                    _applyToSubscription = checked ?? false;
                  });
                  // Also re-trigger speed change if checkbox changes?
                  // Or just wait for next speed selection?
                  // Usually user selects speed THEN checks box or vice versa.
                  // Let's trigger it to be safe if they just want to toggle scope for current speed.
                  widget.onSpeedChanged(PlaybackSpeedSelection(
                    speed: _selectedSpeed,
                    applyToSubscription: _applyToSubscription,
                  ));
                },
                title: Text(AppLocalizations.of(context)!.player_apply_subscription_only),
                subtitle: Text(AppLocalizations.of(context)!.player_apply_subscription_subtitle),
              ),

              const Padding(
                padding: EdgeInsets.symmetric(vertical: 8),
                child: Divider(),
              ),

              // --- Sleep Timer Section ---
              Row(
                children: [
                  Icon(
                    Icons.nightlight_round,
                    color: theme.colorScheme.primary,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    AppLocalizations.of(context)!.player_sleep_timer_title,
                    style: theme.textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  if (widget.isTimerActive &&
                      widget.timerRemainingLabel != null) ...[
                    const Spacer(),
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 8,
                        vertical: 2,
                      ),
                      decoration: BoxDecoration(
                        color: theme.colorScheme.primaryContainer,
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Text(
                        widget.timerRemainingLabel!,
                        style: TextStyle(
                          color: theme.colorScheme.onPrimaryContainer,
                          fontSize: 12,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                  ],
                ],
              ),
              const SizedBox(height: 4),
              Text(
                AppLocalizations.of(context)!.player_sleep_timer_desc,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: _kSleepTimerPresets.map((preset) {
                  return ActionChip(
                    label: Text(_formatPresetDuration(preset, context)),
                    onPressed: () {
                      widget.onTimerChanged(
                        SleepTimerSelection(duration: preset),
                      );
                      Navigator.of(context).pop();
                    },
                  );
                }).toList(),
              ),
              const SizedBox(height: 8),
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(Icons.stop_circle_outlined),
                title: Text(AppLocalizations.of(context)!.player_stop_after_episode),
                onTap: () {
                  widget.onTimerChanged(
                    const SleepTimerSelection.afterEpisode(),
                  );
                  Navigator.of(context).pop();
                },
              ),
              if (widget.isTimerActive)
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: Icon(
                    Icons.timer_off,
                    color: theme.colorScheme.error,
                  ),
                  title: Text(
                    AppLocalizations.of(context)!.player_cancel_timer,
                    style: TextStyle(color: theme.colorScheme.error),
                  ),
                  onTap: () {
                    widget.onTimerChanged(const SleepTimerSelection.cancel());
                    Navigator.of(context).pop();
                  },
                ),
            ],
          ),
        ),
      ),
    );
  }
}
