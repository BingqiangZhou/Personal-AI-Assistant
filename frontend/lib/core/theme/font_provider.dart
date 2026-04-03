import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:personal_ai_assistant/core/constants/app_constants.dart';
import 'package:personal_ai_assistant/core/storage/local_storage_service.dart';
import 'package:personal_ai_assistant/core/theme/font_combination.dart';

const kFontCombinationDefault = 'outfit_literata';

/// Provider for the currently selected font combination.
final fontCombinationProvider =
    NotifierProvider<FontCombinationNotifier, FontCombination>(
  FontCombinationNotifier.new,
);

/// Derived provider exposing the current font combination ID string.
final fontCombinationIdProvider = Provider<String>((ref) {
  return ref.watch(fontCombinationProvider).id;
});

/// Initial font combination ID, overridden at app startup from storage.
final initialFontCombinationIdProvider = Provider<String>(
  (ref) => kFontCombinationDefault,
);

/// Manages the selected font combination state with persistence.
class FontCombinationNotifier extends Notifier<FontCombination> {
  LocalStorageService get _storage => ref.read(localStorageServiceProvider);

  @override
  FontCombination build() {
    final initialId = ref.read(initialFontCombinationIdProvider);
    return FontCombination.fromId(initialId);
  }

  /// The current font combination ID string.
  String get fontCombinationId => state.id;

  /// Set the font combination by ID and persist to storage.
  Future<void> setFontCombination(String id) async {
    state = FontCombination.fromId(id);
    await _storage.saveString(AppConstants.fontCombinationKey, id);
  }

  /// Reset to the default font combination and persist.
  Future<void> resetToDefault() async {
    state = FontCombination.defaultCombination;
    await _storage.saveString(
      AppConstants.fontCombinationKey,
      FontCombination.defaultCombination.id,
    );
  }

  /// Load the saved font combination from storage (called during app init).
  Future<void> loadSavedFontCombination() async {
    final saved = await _storage.getString(AppConstants.fontCombinationKey);
    final id = saved ?? kFontCombinationDefault;
    state = FontCombination.fromId(id);
  }
}
