import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../data/models/audio_player_state_model.dart';
import '../constants/playback_speed_options.dart';
import '../navigation/podcast_navigation.dart';
import '../providers/podcast_providers.dart';
import 'playback_speed_selector_sheet.dart';
import 'podcast_queue_sheet.dart';
import 'sleep_timer_selector_sheet.dart';

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

    return AnimatedSize(
      duration: const Duration(milliseconds: 200),
      curve: Curves.easeInOut,
      alignment: Alignment.bottomCenter,
      child: content,
    );
  }
}

class _MiniBottomPlayer extends ConsumerWidget {
  const _MiniBottomPlayer({super.key, required this.state});

  final AudioPlayerState state;
  static const double _miniHeight = 56;
  static const double _miniRadius = 12;
  static const double _mobileHorizontalInset = 20;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);
    final screenWidth = MediaQuery.of(context).size.width;
    final isWideLayout = screenWidth >= 600;
    final isMobileLayout = !isWideLayout;
    final horizontalInset = isMobileLayout ? _mobileHorizontalInset : 0.0;
    final progressColor = theme.colorScheme.primary;
    final progressTrackColor = progressColor.withValues(alpha: 0.2);

    return Padding(
      key: const Key('podcast_bottom_player_mini_wrapper'),
      padding: EdgeInsets.fromLTRB(
        horizontalInset,
        isWideLayout ? 4 : 0,
        horizontalInset,
        0,
      ),
      child: SizedBox(
        height: _miniHeight,
        child: Material(
          key: const Key('podcast_bottom_player_mini'),
          color: theme.colorScheme.surface,
          elevation: isWideLayout ? 0 : 6,
          clipBehavior: Clip.antiAlias,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(_miniRadius),
            side: BorderSide(
              color: theme.colorScheme.outlineVariant.withValues(alpha: 0.35),
              width: 1,
            ),
          ),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12),
            child: Row(
              children: [
                GestureDetector(
                  onTap: () =>
                      ref.read(audioPlayerProvider.notifier).setExpanded(true),
                  child: _CoverImage(
                    imageUrl:
                        state.currentEpisode!.subscriptionImageUrl ??
                        state.currentEpisode!.imageUrl,
                    size: 42,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: GestureDetector(
                    key: const Key('podcast_bottom_player_mini_info'),
                    behavior: HitTestBehavior.opaque,
                    onTap: () => ref
                        .read(audioPlayerProvider.notifier)
                        .setExpanded(true),
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
                        const SizedBox(height: 3),
                        Row(
                          children: [
                            Expanded(
                              child: ClipRRect(
                                borderRadius: BorderRadius.circular(999),
                                child: LinearProgressIndicator(
                                  key: const Key(
                                    'podcast_bottom_player_mini_progress',
                                  ),
                                  value: state.progress,
                                  minHeight: 3,
                                  color: progressColor,
                                  backgroundColor: progressTrackColor,
                                ),
                              ),
                            ),
                            const SizedBox(width: 8),
                            Text(
                              key: const Key('podcast_bottom_player_mini_time'),
                              '${state.formattedPosition} / ${state.formattedDuration}',
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: theme.textTheme.bodySmall?.copyWith(
                                color: theme.colorScheme.onSurfaceVariant,
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
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
                      : Icon(state.isPlaying ? Icons.pause : Icons.play_arrow),
                ),
                IconButton(
                  key: const Key('podcast_bottom_player_mini_playlist'),
                  tooltip: l10n?.podcast_player_list ?? 'List',
                  onPressed: () => _showQueueSheet(context, ref),
                  icon: const Icon(Icons.playlist_play),
                ),
              ],
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
    final nowPlayingText = l10n?.podcast_player_now_playing ?? 'Now Playing';

    Future<void> showSpeedSelector() async {
      final selection = await showPlaybackSpeedSelectorSheet(
        context: context,
        initialSpeed: state.playbackRate,
      );
      if (!context.mounted || selection == null) return;
      await ref
          .read(audioPlayerProvider.notifier)
          .setPlaybackRate(
            selection.speed,
            applyToSubscription: selection.applyToSubscription,
          );
    }

    Future<void> showSleepSelector() async {
      final selection = await showSleepTimerSelectorSheet(
        context: context,
        isTimerActive: state.isSleepTimerActive,
      );
      if (!context.mounted || selection == null) return;

      final notifier = ref.read(audioPlayerProvider.notifier);
      if (selection.cancel) {
        notifier.cancelSleepTimer();
      } else if (selection.afterEpisode) {
        notifier.setSleepTimerAfterEpisode();
      } else if (selection.duration != null) {
        notifier.setSleepTimer(selection.duration!);
      }
    }

    return Material(
      key: const Key('podcast_bottom_player_expanded'),
      color: theme.colorScheme.surface,
      elevation: 8,
      child: ConstrainedBox(
        constraints: BoxConstraints(
          maxHeight: MediaQuery.of(context).size.height * 0.45,
        ),
        child: SingleChildScrollView(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(12, 6, 12, 10),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Row(
                  children: [
                    Text(
                      nowPlayingText,
                      style: theme.textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const Spacer(),
                    IconButton(
                      key: const Key('podcast_bottom_player_playlist'),
                      tooltip: l10n?.podcast_player_list ?? 'List',
                      onPressed: () => _showQueueSheet(context, ref),
                      icon: const Icon(Icons.playlist_play),
                    ),
                    IconButton(
                      tooltip: l10n?.podcast_player_collapse ?? 'Collapse',
                      onPressed: () => ref
                          .read(audioPlayerProvider.notifier)
                          .setExpanded(false),
                      icon: const Icon(Icons.keyboard_arrow_down),
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
                      child: GestureDetector(
                        key: const Key('podcast_bottom_player_expanded_title'),
                        behavior: HitTestBehavior.opaque,
                        onTap: () {
                          final episode = state.currentEpisode!;
                          final currentLocation = GoRouterState.of(
                            context,
                          ).uri.toString();
                          final episodeDetailPath =
                              '/podcast/episodes/${episode.subscriptionId}/${episode.id}';
                          if (currentLocation.startsWith(episodeDetailPath)) {
                            return;
                          }
                          PodcastNavigation.goToEpisodeDetail(
                            context,
                            episodeId: episode.id,
                            subscriptionId: episode.subscriptionId,
                            episodeTitle: episode.title,
                          );
                        },
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              state.currentEpisode!.title,
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                              style: theme.textTheme.titleSmall?.copyWith(
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            const SizedBox(height: 4),
                            Row(
                              children: [
                                Icon(
                                  Icons.calendar_today_outlined,
                                  size: 12,
                                  color: theme.colorScheme.onSurfaceVariant
                                      .withValues(alpha: 0.7),
                                ),
                                const SizedBox(width: 4),
                                Text(
                                  state.currentEpisode!.publishedAt
                                      .toString()
                                      .split(' ')[0],
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: theme.colorScheme.onSurfaceVariant
                                        .withValues(alpha: 0.7),
                                    fontSize: 11,
                                  ),
                                ),
                                const SizedBox(width: 12),
                                Icon(
                                  Icons.access_time,
                                  size: 12,
                                  color: theme.colorScheme.onSurfaceVariant
                                      .withValues(alpha: 0.7),
                                ),
                                const SizedBox(width: 4),
                                Text(
                                  state.currentEpisode!.formattedDuration,
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: theme.colorScheme.onSurfaceVariant
                                        .withValues(alpha: 0.7),
                                    fontSize: 11,
                                  ),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 6),
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
                const SizedBox(height: 4),
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: _withSpacing([
                    Container(
                      key: const Key('podcast_bottom_player_speed'),
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(16),
                        border: Border.all(
                          color: theme.dividerColor.withValues(alpha: 0.3),
                        ),
                        color: theme.colorScheme.surface.withValues(alpha: 0.5),
                      ),
                      child: InkWell(
                        borderRadius: BorderRadius.circular(16),
                        onTap: showSpeedSelector,
                        child: Padding(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 12,
                            vertical: 10,
                          ),
                          child: Text(
                            formatPlaybackSpeed(state.playbackRate),
                            style: theme.textTheme.labelLarge?.copyWith(
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                      ),
                    ),
                    IconButton(
                      key: const Key('podcast_bottom_player_rewind_10'),
                      tooltip: l10n?.podcast_player_rewind_10 ?? 'Rewind 10s',
                      iconSize: 32,
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
                        iconSize: 48,
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
                                width: 24,
                                height: 24,
                                child: CircularProgressIndicator(
                                  strokeWidth: 3,
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
                      tooltip: l10n?.podcast_player_forward_30 ?? 'Forward 30s',
                      iconSize: 32,
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
                      key: const Key('podcast_bottom_player_sleep'),
                      tooltip: l10n?.podcast_player_sleep_mode ?? 'Sleep Mode',
                      iconSize: 32,
                      onPressed: showSleepSelector,
                      icon: const Icon(Icons.nights_stay_rounded),
                    ),
                  ]),
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
                errorBuilder: (_, error, stackTrace) => _fallback(theme),
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

Future<void> _showQueueSheet(BuildContext context, WidgetRef ref) async {
  await PodcastQueueSheet.show(
    context,
    beforeShow: () async {
      await ref.read(podcastQueueControllerProvider.notifier).loadQueue();
    },
  );
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
