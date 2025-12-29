import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Bulk selection state for podcast subscriptions
class BulkSelectionState {
  final Set<int> selectedIds;
  final bool isSelectionMode;

  const BulkSelectionState({
    this.selectedIds = const {},
    this.isSelectionMode = false,
  });

  BulkSelectionState copyWith({
    Set<int>? selectedIds,
    bool? isSelectionMode,
  }) {
    return BulkSelectionState(
      selectedIds: selectedIds ?? this.selectedIds,
      isSelectionMode: isSelectionMode ?? this.isSelectionMode,
    );
  }

  int get count => selectedIds.length;
  bool get isSelectedAll => isSelectionMode && selectedIds.isNotEmpty;

  /// Check if a subscription is selected
  bool isSelected(int subscriptionId) {
    return selectedIds.contains(subscriptionId);
  }
}

/// Notifier for managing bulk selection state
class BulkSelectionNotifier extends Notifier<BulkSelectionState> {
  @override
  BulkSelectionState build() {
    return const BulkSelectionState();
  }

  /// Toggle selection mode
  void toggleSelectionMode() {
    if (state.isSelectionMode) {
      // Exit selection mode and clear selections
      state = const BulkSelectionState();
    } else {
      // Enter selection mode
      state = state.copyWith(isSelectionMode: true);
    }
  }

  /// Toggle selection for a specific subscription
  void toggleSelection(int subscriptionId) {
    final newSelectedIds = Set<int>.from(state.selectedIds);
    if (newSelectedIds.contains(subscriptionId)) {
      newSelectedIds.remove(subscriptionId);
    } else {
      newSelectedIds.add(subscriptionId);
    }

    state = state.copyWith(
      selectedIds: newSelectedIds,
      // Auto exit selection mode if nothing is selected
      isSelectionMode: newSelectedIds.isNotEmpty || state.isSelectionMode,
    );
  }

  /// Select all subscriptions
  void selectAll(List<int> allIds) {
    state = state.copyWith(
      selectedIds: Set<int>.from(allIds),
      isSelectionMode: true,
    );
  }

  /// Deselect all subscriptions
  void deselectAll() {
    state = state.copyWith(
      selectedIds: {},
      isSelectionMode: true, // Keep selection mode active
    );
  }

  /// Clear selection and exit selection mode
  void clearSelection() {
    state = const BulkSelectionState();
  }
}

/// Provider for bulk selection state
final bulkSelectionProvider =
    NotifierProvider<BulkSelectionNotifier, BulkSelectionState>(
  BulkSelectionNotifier.new,
);
