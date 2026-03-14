part of 'podcast_bottom_player_widget.dart';

BuildContext _resolveNavigatorContext(BuildContext context) {
  final navContext = appNavigatorKey.currentContext;
  if (navContext != null && navContext.mounted) {
    return navContext;
  }
  return context;
}

void _openExpandedPlayer(WidgetRef ref) {
  ref.read(podcastPlayerUiProvider.notifier).expand();
}

Future<void> _showSpeedSelector(BuildContext context, WidgetRef ref) async {
  final notifier = ref.read(audioPlayerProvider.notifier);
  final selectionState = notifier.getPlaybackRateSelectionSnapshot();
  final selection = await showPlaybackSpeedSelectorSheet(
    context: _resolveNavigatorContext(context),
    initialSpeed: selectionState.speed,
    initialApplyToSubscription: selectionState.applyToSubscription,
    correctedInitialSelection: notifier
        .resolvePlaybackRateSelectionForCurrentContext(),
    allowApplyToSubscription: ref.read(audioCurrentEpisodeProvider) != null,
  );
  if (selection == null) {
    return;
  }
  await notifier.setPlaybackRate(
    selection.speed,
    applyToSubscription: selection.applyToSubscription,
  );
}

Future<void> _showSleepSelector(BuildContext context, WidgetRef ref) async {
  final isTimerActive = ref.read(audioSleepTimerActiveProvider);
  final selection = await showSleepTimerSelectorSheet(
    context: _resolveNavigatorContext(context),
    isTimerActive: isTimerActive,
  );
  if (selection == null) {
    return;
  }

  final notifier = ref.read(audioPlayerProvider.notifier);
  if (selection.cancel) {
    notifier.cancelSleepTimer();
  } else if (selection.afterEpisode) {
    notifier.setSleepTimerAfterEpisode();
  } else if (selection.duration != null) {
    notifier.setSleepTimer(selection.duration!);
  }
}

String _formatMilliseconds(int value) {
  final milliseconds = value.clamp(0, 1 << 31);
  return TimeFormatter.formatDuration(
    Duration(milliseconds: milliseconds),
    padHours: false,
  );
}

Future<void> _showQueueSheet(BuildContext context, WidgetRef ref) async {
  final modalContext = _resolveNavigatorContext(context);
  if (!modalContext.mounted) {
    return;
  }

  final uiNotifier = ref.read(podcastPlayerUiProvider.notifier);
  final uiState = ref.read(podcastPlayerUiProvider);
  if (uiState.queueSheetOpen) {
    return;
  }

  final queueController = ref.read(podcastQueueControllerProvider.notifier);
  final queueState = ref.read(podcastQueueControllerProvider);

  uiNotifier.openQueueSheet();
  try {
    final showFuture = PodcastQueueSheet.show(modalContext);
    unawaited(() async {
      try {
        await queueController.loadQueue(forceRefresh: queueState.hasValue);
      } catch (error) {
        logger.AppLogger.warning(
          '[PodcastQueueSheet] Prefetch queue failed: $error',
        );
      }
    }());
    await showFuture;
  } finally {
    uiNotifier.closeQueueSheet();
  }
}
