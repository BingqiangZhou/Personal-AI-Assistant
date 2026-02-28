enum TranscriptionStepStatus { pending, current, completed }

double _clampProgress(double progressPercentage) {
  return progressPercentage.clamp(0.0, 100.0);
}

int transcriptionCurrentStepNumber(double progressPercentage) {
  final progress = _clampProgress(progressPercentage);
  if (progress >= 95) return 5;
  if (progress >= 45) return 4;
  if (progress >= 35) return 3;
  if (progress >= 20) return 2;
  if (progress >= 5) return 1;
  return 0;
}

int transcriptionActiveStepIndex(double progressPercentage) {
  final currentStep = transcriptionCurrentStepNumber(progressPercentage);
  if (currentStep <= 0) {
    return 0;
  }
  return (currentStep - 1).clamp(0, 4);
}

TranscriptionStepStatus transcriptionStepStatusAt(
  double progressPercentage,
  int stepIndex,
) {
  final activeIndex = transcriptionActiveStepIndex(progressPercentage);
  if (stepIndex < activeIndex) {
    return TranscriptionStepStatus.completed;
  }
  if (stepIndex == activeIndex) {
    return TranscriptionStepStatus.current;
  }
  return TranscriptionStepStatus.pending;
}

bool transcriptionConnectorHighlighted(
  double progressPercentage,
  int connectorIndex,
) {
  final activeIndex = transcriptionActiveStepIndex(progressPercentage);
  return connectorIndex < activeIndex;
}
