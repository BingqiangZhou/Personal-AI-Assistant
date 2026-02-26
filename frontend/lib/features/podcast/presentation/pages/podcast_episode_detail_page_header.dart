part of 'podcast_episode_detail_page.dart';

extension _PodcastEpisodeDetailPageHeader on _PodcastEpisodeDetailPageState {
  Widget _buildHeader(dynamic episode) {
    final l10n = (AppLocalizations.of(context) ?? AppLocalizationsEn());

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      color: Theme.of(context).colorScheme.surface,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          PodcastImageWidget(
            imageUrl: episode.imageUrl,
            fallbackImageUrl: episode.subscriptionImageUrl,
            width: 60,
            height: 60,
            iconSize: 32,
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Flexible(
                            child: Text(
                              episode.title ?? l10n.episode_unknown_title,
                              style: TextStyle(
                                fontSize: 16,
                                fontWeight: FontWeight.bold,
                                color: Theme.of(context).colorScheme.onSurface,
                              ),
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          const SizedBox(width: 8),
                          InkWell(
                            onTap: () async {
                              try {
                                await _playOrResumeFromDetail(
                                  _episodeToModel(episode),
                                );
                              } catch (error) {
                                logger.AppLogger.debug(
                                  '[Error] Failed to play episode: $error',
                                );
                              }
                            },
                            child: Container(
                              key: const Key(
                                'podcast_episode_detail_play_button',
                              ),
                              padding: const EdgeInsets.symmetric(
                                horizontal: 10,
                                vertical: 4,
                              ),
                              decoration: BoxDecoration(
                                color: Theme.of(
                                  context,
                                ).colorScheme.primary.withValues(alpha: 0.1),
                                borderRadius: BorderRadius.circular(16),
                                border: Border.all(
                                  color: Theme.of(
                                    context,
                                  ).colorScheme.primary.withValues(alpha: 0.3),
                                  width: 1,
                                ),
                              ),
                              child: Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Icon(
                                    Icons.play_arrow,
                                    size: 18,
                                    color: Theme.of(
                                      context,
                                    ).colorScheme.primary,
                                  ),
                                  const SizedBox(width: 4),
                                  Text(
                                    MediaQuery.of(context).size.width < 600
                                        ? l10n.podcast_play_episode
                                        : l10n.podcast_play_episode_full,
                                    style: TextStyle(
                                      fontSize: 13,
                                      fontWeight: FontWeight.w600,
                                      color: Theme.of(
                                        context,
                                      ).colorScheme.primary,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 8),
                    if (!_isMobilePlatform())
                      Container(
                        decoration: BoxDecoration(
                          color: Theme.of(
                            context,
                          ).colorScheme.primary.withValues(alpha: 0.1),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(
                            color: Theme.of(
                              context,
                            ).colorScheme.primary.withValues(alpha: 0.3),
                            width: 1,
                          ),
                        ),
                        child: IconButton(
                          icon: Icon(
                            Icons.arrow_back,
                            color: Theme.of(context).colorScheme.primary,
                            size: 20,
                          ),
                          onPressed: () => context.pop(),
                          tooltip:
                              (AppLocalizations.of(context) ??
                                      AppLocalizationsEn())
                                  .back_button,
                          constraints: const BoxConstraints(
                            minWidth: 36,
                            minHeight: 36,
                          ),
                          padding: EdgeInsets.zero,
                        ),
                      ),
                  ],
                ),
                const SizedBox(height: 8),
                Wrap(
                  spacing: 16,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  children: [
                    // Published date
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          Icons.calendar_today_outlined,
                          size: 14,
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                        const SizedBox(width: 6),
                        Text(
                          _formatDate(episode.publishedAt),
                          style: TextStyle(
                            fontSize: 13,
                            color: Theme.of(
                              context,
                            ).colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                    // Duration
                    if (episode.audioDuration != null)
                      Consumer(
                        builder: (context, ref, _) {
                          final audioPlayerState = ref.watch(
                            audioPlayerProvider,
                          );
                          // Use audio player duration if available (more accurate), otherwise fall back to episode duration
                          // CRITICAL: episode.audioDuration is in SECONDS, convert to MILLISECONDS
                          final displayDuration =
                              (audioPlayerState.currentEpisode?.id ==
                                      episode.id &&
                                  audioPlayerState.duration > 0)
                              ? audioPlayerState.duration
                              : (episode.audioDuration! *
                                    1000); // Convert seconds to milliseconds
                          final duration = Duration(
                            milliseconds: displayDuration,
                          );
                          final hours = duration.inHours;
                          final minutes = duration.inMinutes.remainder(60);
                          final seconds = duration.inSeconds.remainder(60);

                          // Format as H:MM:SS or MM:SS depending on whether hours exist
                          final formattedDuration = hours > 0
                              ? '$hours:${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}'
                              : '${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';

                          return Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Icon(
                                Icons.schedule_outlined,
                                size: 14,
                                color: Theme.of(
                                  context,
                                ).colorScheme.onSurfaceVariant,
                              ),
                              const SizedBox(width: 6),
                              Text(
                                formattedDuration,
                                style: TextStyle(
                                  fontSize: 13,
                                  color: Theme.of(
                                    context,
                                  ).colorScheme.onSurfaceVariant,
                                ),
                              ),
                            ],
                          );
                        },
                      ),
                    // Source link
                    if (episode.itemLink != null &&
                        episode.itemLink!.isNotEmpty)
                      InkWell(
                        onTap: () async {
                          final Uri linkUri = Uri.parse(episode.itemLink!);
                          if (await canLaunchUrl(linkUri)) {
                            await launchUrl(
                              linkUri,
                              mode: LaunchMode.externalApplication,
                            );
                          }
                        },
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.link,
                              size: 14,
                              color: Theme.of(context).colorScheme.primary,
                            ),
                            const SizedBox(width: 6),
                            Text(
                              l10n.podcast_source,
                              style: TextStyle(
                                fontSize: 13,
                                color: Theme.of(context).colorScheme.primary,
                              ),
                            ),
                          ],
                        ),
                      ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildAnimatedHeader(dynamic episode) {
    final l10n = (AppLocalizations.of(context) ?? AppLocalizationsEn());

    if (_isHeaderExpanded) {
      return Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surface,
          border: Border(
            bottom: BorderSide(
              color: Theme.of(context).colorScheme.outlineVariant,
              width: 1,
            ),
          ),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            PodcastImageWidget(
              imageUrl: episode.imageUrl,
              fallbackImageUrl: episode.subscriptionImageUrl,
              width: 60,
              height: 60,
              iconSize: 32,
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          episode.title ?? l10n.episode_unknown_title,
                          style: TextStyle(
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                            color: Theme.of(context).colorScheme.onSurface,
                          ),
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      const SizedBox(width: 12),
                      _buildPlayButton(episode, l10n),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Wrap(
                    spacing: 16,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      _buildDateChip(episode),
                      if (episode.audioDuration != null)
                        _buildDurationChip(episode),
                      if (episode.itemLink != null &&
                          episode.itemLink!.isNotEmpty)
                        _buildSourceLinkChip(episode, l10n),
                    ],
                  ),
                ],
              ),
            ),
            const SizedBox(width: 16),
            _buildBackButton(),
          ],
        ),
      );
    } else {
      return Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surface,
          border: Border(
            right: BorderSide(
              color: Theme.of(context).colorScheme.outlineVariant,
              width: 1,
            ),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Center(
              child: PodcastImageWidget(
                imageUrl: episode.imageUrl,
                fallbackImageUrl: episode.subscriptionImageUrl,
                width: 40,
                height: 40,
                iconSize: 24,
              ),
            ),
            const SizedBox(height: 6),
            Text(
              episode.title ?? 'Unknown',
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w600,
                color: Theme.of(context).colorScheme.onSurface,
              ),
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              textAlign: TextAlign.center,
            ),
          ],
        ),
      );
    }
  }

  PodcastEpisodeModel _episodeToModel(dynamic episode) {
    return PodcastEpisodeModel(
      id: episode.id,
      subscriptionId: episode.subscriptionId,
      subscriptionImageUrl: episode.subscriptionImageUrl,
      title: episode.title,
      description: episode.description,
      audioUrl: episode.audioUrl,
      audioDuration: episode.audioDuration,
      audioFileSize: episode.audioFileSize,
      publishedAt: episode.publishedAt,
      imageUrl: episode.imageUrl,
      itemLink: episode.itemLink,
      transcriptUrl: episode.transcriptUrl,
      transcriptContent: episode.transcriptContent,
      aiSummary: episode.aiSummary,
      summaryVersion: episode.summaryVersion,
      aiConfidenceScore: episode.aiConfidenceScore,
      playCount: episode.playCount,
      lastPlayedAt: episode.lastPlayedAt,
      season: episode.season,
      episodeNumber: episode.episodeNumber,
      explicit: episode.explicit,
      status: episode.status,
      metadata: episode.metadata,
      playbackPosition: episode.playbackPosition,
      isPlaying: episode.isPlaying,
      playbackRate: episode.playbackRate,
      isPlayed: episode.isPlayed ?? false,
      createdAt: episode.createdAt,
      updatedAt: episode.updatedAt,
    );
  }

  Future<void> _playOrResumeFromDetail(PodcastEpisodeModel episodeModel) async {
    final notifier = ref.read(audioPlayerProvider.notifier);
    final playerState = ref.read(audioPlayerProvider);
    final isSameEpisode = playerState.currentEpisode?.id == episodeModel.id;
    final isCompleted =
        playerState.processingState == ProcessingState.completed;

    if (isSameEpisode && !isCompleted) {
      if (playerState.isPlaying) {
        return;
      }
      await notifier.resume();
      return;
    }

    await notifier.playEpisode(episodeModel);
  }

  Future<void> _addCurrentEpisodeToQueue() async {
    if (_isAddingToQueue) {
      return;
    }
    _updatePageState(() {
      _isAddingToQueue = true;
    });

    try {
      await ref
          .read(podcastQueueControllerProvider.notifier)
          .addToQueue(widget.episodeId);
      if (mounted) {
        final l10n = (AppLocalizations.of(context) ?? AppLocalizationsEn());
        showTopFloatingNotice(
          context,
          message: l10n.added_to_queue,
          extraTopOffset: 72,
        );
      }
    } catch (error) {
      if (mounted) {
        final l10n = (AppLocalizations.of(context) ?? AppLocalizationsEn());
        showTopFloatingNotice(
          context,
          message: l10n.failed_to_add_to_queue(error.toString()),
          isError: true,
          extraTopOffset: 72,
        );
      }
    } finally {
      if (mounted) {
        _updatePageState(() {
          _isAddingToQueue = false;
        });
      }
    }
  }

  Widget _buildPlayButton(dynamic episode, AppLocalizations l10n) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        InkWell(
          onTap: () async {
            try {
              await _playOrResumeFromDetail(_episodeToModel(episode));
            } catch (error) {
              logger.AppLogger.debug('[Error] Failed to play episode: $error');
            }
          },
          child: Container(
            key: const Key('podcast_episode_detail_play_button'),
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            decoration: BoxDecoration(
              color: Theme.of(
                context,
              ).colorScheme.primary.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(20),
              border: Border.all(
                color: Theme.of(
                  context,
                ).colorScheme.primary.withValues(alpha: 0.3),
                width: 1,
              ),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  Icons.play_arrow,
                  size: 18,
                  color: Theme.of(context).colorScheme.primary,
                ),
                const SizedBox(width: 4),
                Text(
                  l10n.podcast_play_episode_full,
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(width: 8),
        InkWell(
          key: const Key('podcast_episode_detail_add_to_queue'),
          onTap: _isAddingToQueue ? null : _addCurrentEpisodeToQueue,
          child: Container(
            padding: const EdgeInsets.all(6),
            decoration: BoxDecoration(
              color: Theme.of(
                context,
              ).colorScheme.primary.withValues(alpha: 0.08),
              borderRadius: BorderRadius.circular(18),
              border: Border.all(
                color: Theme.of(
                  context,
                ).colorScheme.primary.withValues(alpha: 0.3),
                width: 1,
              ),
            ),
            child: _isAddingToQueue
                ? SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                  )
                : Icon(
                    Icons.playlist_add,
                    size: 18,
                    color: Theme.of(context).colorScheme.primary,
                  ),
          ),
        ),
      ],
    );
  }

  Widget _buildCollapsedFloatingActions(
    dynamic episode,
    AppLocalizations l10n,
  ) {
    return Container(
      key: const Key('podcast_episode_detail_collapsed_actions'),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          _buildBackButton(),
          const SizedBox(width: 8),
          _buildPlayButton(episode, l10n),
        ],
      ),
    );
  }

  Widget _buildBackButton() {
    return Container(
      width: 32,
      height: 32,
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
          width: 1,
        ),
      ),
      child: InkWell(
        onTap: () => context.pop(),
        borderRadius: BorderRadius.circular(8),
        child: Center(
          child: Icon(
            Icons.arrow_back,
            color: Theme.of(context).colorScheme.primary,
            size: 18,
          ),
        ),
      ),
    );
  }

  Widget _buildDateChip(dynamic episode) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(
          Icons.calendar_today_outlined,
          size: 14,
          color: Theme.of(context).colorScheme.onSurfaceVariant,
        ),
        const SizedBox(width: 6),
        Text(
          _formatDate(episode.publishedAt),
          style: TextStyle(
            fontSize: 13,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
      ],
    );
  }

  Widget _buildDurationChip(dynamic episode) {
    return Consumer(
      builder: (context, ref, _) {
        final audioPlayerState = ref.watch(audioPlayerProvider);
        final displayDuration =
            (audioPlayerState.currentEpisode?.id == episode.id &&
                audioPlayerState.duration > 0)
            ? audioPlayerState.duration
            : (episode.audioDuration! * 1000);
        final duration = Duration(milliseconds: displayDuration);
        final hours = duration.inHours;
        final minutes = duration.inMinutes.remainder(60);
        final seconds = duration.inSeconds.remainder(60);

        final formattedDuration = hours > 0
            ? '$hours:${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}'
            : '${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';

        return Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.schedule_outlined,
              size: 14,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            const SizedBox(width: 6),
            Text(
              formattedDuration,
              style: TextStyle(
                fontSize: 13,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        );
      },
    );
  }

  Widget _buildSourceLinkChip(dynamic episode, AppLocalizations l10n) {
    return InkWell(
      onTap: () async {
        final Uri linkUri = Uri.parse(episode.itemLink!);
        if (await canLaunchUrl(linkUri)) {
          await launchUrl(linkUri, mode: LaunchMode.externalApplication);
        }
      },
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.link,
            size: 14,
            color: Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(width: 6),
          Text(
            l10n.podcast_source,
            style: TextStyle(
              fontSize: 13,
              color: Theme.of(context).colorScheme.primary,
            ),
          ),
        ],
      ),
    );
  }
}
