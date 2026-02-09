import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/playback_progress_policy.dart';

void main() {
  group('normalizeResumePositionMs', () {
    test('restores seconds as milliseconds for normal progress', () {
      final result = normalizeResumePositionMs(120, 1800);
      expect(result, 120000);
    });

    test('resets to zero when position is within tail threshold', () {
      final result = normalizeResumePositionMs(1799, 1800);
      expect(result, 0);
    });
  });

  group('buildPersistPayload', () {
    test('resets to zero and paused when near completed tail', () {
      final payload = buildPersistPayload(1799000, 1800000, true);
      expect(payload.positionSec, 0);
      expect(payload.isPlaying, isFalse);
    });

    test('keeps normal middle progress with second rounding', () {
      final payload = buildPersistPayload(120400, 1800000, true);
      expect(payload.positionSec, 120);
      expect(payload.isPlaying, isTrue);
    });

    test('clamps negative milliseconds to zero seconds', () {
      final payload = buildPersistPayload(-1000, 1800000, false);
      expect(payload.positionSec, 0);
      expect(payload.isPlaying, isFalse);
    });
  });
}
