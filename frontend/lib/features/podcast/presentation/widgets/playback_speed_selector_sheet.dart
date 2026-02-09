import 'package:flutter/material.dart';

import '../constants/playback_speed_options.dart';

class PlaybackSpeedSelection {
  final double speed;
  final bool applyToSubscription;

  const PlaybackSpeedSelection({
    required this.speed,
    required this.applyToSubscription,
  });
}

Future<PlaybackSpeedSelection?> showPlaybackSpeedSelectorSheet({
  required BuildContext context,
  required double initialSpeed,
  bool initialApplyToSubscription = false,
}) {
  return showModalBottomSheet<PlaybackSpeedSelection>(
    context: context,
    showDragHandle: true,
    builder: (context) {
      var selectedSpeed = initialSpeed;
      var applyToSubscription = initialApplyToSubscription;
      final theme = Theme.of(context);

      return StatefulBuilder(
        builder: (context, setState) {
          return SafeArea(
            child: SingleChildScrollView(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Playback Speed',
                      style: theme.textTheme.titleMedium?.copyWith(
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: 12),
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: kPlaybackSpeedOptions.map((speed) {
                        return ChoiceChip(
                          label: Text(formatPlaybackSpeed(speed)),
                          selected: (selectedSpeed - speed).abs() < 0.0001,
                          onSelected: (_) {
                            setState(() {
                              selectedSpeed = speed;
                            });
                          },
                        );
                      }).toList(),
                    ),
                    const SizedBox(height: 8),
                    CheckboxListTile(
                      contentPadding: EdgeInsets.zero,
                      value: applyToSubscription,
                      onChanged: (checked) {
                        setState(() {
                          applyToSubscription = checked ?? false;
                        });
                      },
                      title: const Text(
                        'Only apply to current show (current subscription)',
                      ),
                      subtitle: const Text(
                        'Checked: subscription only; unchecked: global',
                      ),
                    ),
                    const SizedBox(height: 8),
                    SizedBox(
                      width: double.infinity,
                      child: FilledButton(
                        onPressed: () {
                          Navigator.of(context).pop(
                            PlaybackSpeedSelection(
                              speed: selectedSpeed,
                              applyToSubscription: applyToSubscription,
                            ),
                          );
                        },
                        child: const Text('Apply'),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          );
        },
      );
    },
  );
}
