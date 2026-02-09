import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../data/models/audio_player_state_model.dart';
import '../providers/podcast_providers.dart';
import 'podcast_queue_sheet.dart';

class PodcastBottomPlayerWidget extends ConsumerWidget {
  const PodcastBottomPlayerWidget({super.key, this.applySafeArea = true});

  final bool applySafeArea;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(audioPlayerProvider);
    final episode = state.currentEpisode;
    if (episode == null) {
      return const SizedBox.shrink();
    }

    Widget content = AnimatedSwitcher(
      duration: const Duration(milliseconds: 200),
      child: state.isExpanded
          ? _ExpandedBottomPlayer(key: const ValueKey('expanded'), state: state)
          : _MiniBottomPlayer(key: const ValueKey('mini'), state: state),
    );

    if (applySafeArea) {
      content = SafeArea(top: false, child: content);
    }

    return content;
  }
}

class _MiniBottomPlayer extends ConsumerWidget {
  const _MiniBottomPlayer({super.key, required this.state});

  final AudioPlayerState state;
  static const double _miniHeight = 56;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);
    final isWideLayout = MediaQuery.of(context).size.width >= 600;

    return Padding(
      key: const Key('podcast_bottom_player_mini_wrapper'),
      padding: EdgeInsets.symmetric(vertical: isWideLayout ? 4 : 0),
      child: Material(
        key: const Key('podcast_bottom_player_mini'),
        color: theme.colorScheme.surface,
        elevation: isWideLayout ? 0 : 6,
        child: InkWell(
          onTap: () => ref.read(audioPlayerProvider.notifier).setExpanded(true),
          child: SizedBox(
            height: _miniHeight,
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              child: Row(
                children: [
                  _CoverImage(
                    imageUrl:
                        state.currentEpisode!.subscriptionImageUrl ??
                        state.currentEpisode!.imageUrl,
                    size: 42,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          state.currentEpisode!.title,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: theme.textTheme.titleSmall?.copyWith(
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Text(
                          state.formattedPosition,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  ),
                  IconButton(
                    key: const Key('podcast_bottom_player_mini_play_pause'),
                    tooltip: state.isPlaying
                        ? (l10n?.podcast_player_pause ?? 'Pause')
                        : (l10n?.podcast_player_play ?? 'Play'),
                    onPressed: () async {
                      if (state.isLoading) return;
                      if (state.isPlaying) {
                        await ref.read(audioPlayerProvider.notifier).pause();
                      } else {
                        await ref.read(audioPlayerProvider.notifier).resume();
                      }
                    },
                    icon: state.isLoading
                        ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : Icon(
                            state.isPlaying ? Icons.pause : Icons.play_arrow,
                          ),
                  ),
                  IconButton(
                    key: const Key('podcast_bottom_player_mini_playlist'),
                    tooltip: l10n?.podcast_player_list ?? 'List',
                    onPressed: () async {
                      await ref
                          .read(podcastQueueControllerProvider.notifier)
                          .loadQueue();
                      if (!context.mounted) {
                        return;
                      }
                      await PodcastQueueSheet.show(context);
                    },
                    icon: const Icon(Icons.playlist_play),
                  ),
                  Icon(
                    Icons.keyboard_arrow_up,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _ExpandedBottomPlayer extends ConsumerWidget {
  const _ExpandedBottomPlayer({super.key, required this.state});

  final AudioPlayerState state;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);
    final maxSlider = state.duration > 0 ? state.duration.toDouble() : 1.0;
    final sliderValue = state.position.toDouble().clamp(0.0, maxSlider);

    return Material(
      key: const Key('podcast_bottom_player_expanded'),
      color: theme.colorScheme.surface,
      elevation: 8,
      child: SizedBox(
        height: 248,
        child: SingleChildScrollView(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(12, 8, 12, 12),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Row(
                  children: [
                    Text(
                      l10n?.podcast_player_now_playing ?? 'Now Playing',
                      style: theme.textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const Spacer(),
                    IconButton(
                      tooltip: l10n?.podcast_player_collapse ?? 'Collapse',
                      onPressed: () => ref
                          .read(audioPlayerProvider.notifier)
                          .setExpanded(false),
                      icon: const Icon(Icons.keyboard_arrow_down),
                    ),
                    IconButton(
                      tooltip: 'Close',
                      onPressed: () =>
                          ref.read(audioPlayerProvider.notifier).stop(),
                      icon: const Icon(Icons.close),
                    ),
                  ],
                ),
                Row(
                  children: [
                    _CoverImage(
                      imageUrl:
                          state.currentEpisode!.subscriptionImageUrl ??
                          state.currentEpisode!.imageUrl,
                      size: 52,
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        state.currentEpisode!.title,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: theme.textTheme.titleSmall?.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 10),
                Slider(
                  value: sliderValue,
                  max: maxSlider,
                  onChanged: (value) => ref
                      .read(audioPlayerProvider.notifier)
                      .seekTo(value.round()),
                ),
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 4),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        state.formattedPosition,
                        style: theme.textTheme.bodySmall,
                      ),
                      Text(
                        state.formattedDuration,
                        style: theme.textTheme.bodySmall,
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 8),
                LayoutBuilder(
                  builder: (context, constraints) {
                    final controls = <Widget>[
                      PopupMenuButton<double>(
                        key: const Key('podcast_bottom_player_speed'),
                        tooltip:
                            l10n?.podcast_player_playback_speed ??
                            'Playback speed',
                        onSelected: (value) => ref
                            .read(audioPlayerProvider.notifier)
                            .setPlaybackRate(value),
                        itemBuilder: (context) => const [
                          PopupMenuItem(value: 0.5, child: Text('0.5x')),
                          PopupMenuItem(value: 0.75, child: Text('0.75x')),
                          PopupMenuItem(value: 1.0, child: Text('1.0x')),
                          PopupMenuItem(value: 1.25, child: Text('1.25x')),
                          PopupMenuItem(value: 1.5, child: Text('1.5x')),
                          PopupMenuItem(value: 2.0, child: Text('2.0x')),
                        ],
                        child: SizedBox(
                          height: 48,
                          child: Center(
                            child: Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 8,
                                vertical: 4,
                              ),
                              decoration: BoxDecoration(
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(
                                  color: theme.colorScheme.outlineVariant,
                                ),
                              ),
                              child: Text(
                                '${state.playbackRate}x',
                                style: theme.textTheme.labelMedium,
                              ),
                            ),
                          ),
                        ),
                      ),
                      IconButton(
                        key: const Key('podcast_bottom_player_rewind_10'),
                        tooltip: l10n?.podcast_player_rewind_10 ?? 'Rewind 10s',
                        onPressed: () {
                          final next = (state.position - 10000).clamp(
                            0,
                            state.duration,
                          );
                          ref.read(audioPlayerProvider.notifier).seekTo(next);
                        },
                        icon: const Icon(Icons.replay_10),
                      ),
                      Container(
                        decoration: BoxDecoration(
                          color: theme.colorScheme.primaryContainer,
                          shape: BoxShape.circle,
                        ),
                        child: IconButton(
                          key: const Key('podcast_bottom_player_play_pause'),
                          tooltip: state.isPlaying
                              ? (l10n?.podcast_player_pause ?? 'Pause')
                              : (l10n?.podcast_player_play ?? 'Play'),
                          onPressed: () async {
                            if (state.isLoading) return;
                            if (state.isPlaying) {
                              await ref
                                  .read(audioPlayerProvider.notifier)
                                  .pause();
                            } else {
                              await ref
                                  .read(audioPlayerProvider.notifier)
                                  .resume();
                            }
                          },
                          icon: state.isLoading
                              ? const SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                  ),
                                )
                              : Icon(
                                  state.isPlaying
                                      ? Icons.pause
                                      : Icons.play_arrow,
                                ),
                        ),
                      ),
                      IconButton(
                        key: const Key('podcast_bottom_player_forward_30'),
                        tooltip:
                            l10n?.podcast_player_forward_30 ?? 'Forward 30s',
                        onPressed: () {
                          final next = (state.position + 30000).clamp(
                            0,
                            state.duration,
                          );
                          ref.read(audioPlayerProvider.notifier).seekTo(next);
                        },
                        icon: const Icon(Icons.forward_30),
                      ),
                      IconButton(
                        key: const Key('podcast_bottom_player_playlist'),
                        tooltip: l10n?.podcast_player_list ?? 'List',
                        onPressed: () async {
                          await ref
                              .read(podcastQueueControllerProvider.notifier)
                              .loadQueue();
                          if (!context.mounted) {
                            return;
                          }
                          await PodcastQueueSheet.show(context);
                        },
                        icon: const Icon(Icons.playlist_play),
                      ),
                    ];

                    if (constraints.maxWidth >= 360) {
                      return Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: _withSpacing(controls),
                      );
                    }

                    return Wrap(
                      alignment: WrapAlignment.center,
                      crossAxisAlignment: WrapCrossAlignment.center,
                      spacing: 8,
                      runSpacing: 8,
                      children: controls,
                    );
                  },
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _CoverImage extends StatelessWidget {
  const _CoverImage({required this.imageUrl, required this.size});

  final String? imageUrl;
  final double size;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ClipRRect(
      borderRadius: BorderRadius.circular(8),
      child: SizedBox(
        width: size,
        height: size,
        child: imageUrl != null && imageUrl!.isNotEmpty
            ? Image.network(
                imageUrl!,
                fit: BoxFit.cover,
                errorBuilder: (_, __, ___) => _fallback(theme),
              )
            : _fallback(theme),
      ),
    );
  }

  Widget _fallback(ThemeData theme) {
    return Container(
      color: theme.colorScheme.primary.withValues(alpha: 0.12),
      alignment: Alignment.center,
      child: Icon(Icons.podcasts, color: theme.colorScheme.primary),
    );
  }
}

List<Widget> _withSpacing(List<Widget> children, {double spacing = 8}) {
  if (children.isEmpty) return const [];

  final result = <Widget>[];
  for (var i = 0; i < children.length; i++) {
    if (i > 0) {
      result.add(SizedBox(width: spacing));
    }
    result.add(children[i]);
  }
  return result;
}
