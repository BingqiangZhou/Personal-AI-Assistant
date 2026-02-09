class PlaybackPersistPayload {
  final int positionSec;
  final bool isPlaying;

  const PlaybackPersistPayload({
    required this.positionSec,
    required this.isPlaying,
  });
}

int normalizeResumePositionMs(
  int? savedPositionSec,
  int? durationSec, {
  int tailSec = 2,
}) {
  final positionSec = (savedPositionSec ?? 0).clamp(0, 1 << 31);
  if (positionSec <= 0) {
    return 0;
  }

  if (durationSec != null && durationSec > 0) {
    final completedThresholdSec = durationSec - tailSec;
    if (positionSec >= completedThresholdSec) {
      return 0;
    }
    final clampedSec = positionSec > durationSec ? durationSec : positionSec;
    return clampedSec * 1000;
  }

  return positionSec * 1000;
}

PlaybackPersistPayload buildPersistPayload(
  int positionMs,
  int durationMs,
  bool isPlaying, {
  int tailSec = 2,
}) {
  var positionSec = (positionMs / 1000).round();
  if (positionSec < 0) {
    positionSec = 0;
  }

  if (durationMs > 0) {
    final durationSec = (durationMs / 1000).round();
    if (durationSec > 0) {
      final completedThresholdSec = durationSec - tailSec;
      if (positionSec >= completedThresholdSec) {
        return const PlaybackPersistPayload(positionSec: 0, isPlaying: false);
      }
      if (positionSec > durationSec) {
        positionSec = durationSec;
      }
    }
  }

  return PlaybackPersistPayload(positionSec: positionSec, isPlaying: isPlaying);
}
