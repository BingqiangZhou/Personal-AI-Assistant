import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:personal_ai_assistant/core/constants/app_constants.dart';
import 'package:personal_ai_assistant/core/storage/local_storage_service.dart';
import 'package:personal_ai_assistant/core/theme/font_combination.dart';

const kFontCombinationDefault = 'space_grotesk_inter';

/// Provider for the currently selected font combination.
final fontCombinationProvider =
    NotifierProvider<FontCombinationNotifier, FontCombination>(
  FontCombinationNotifier.new,
);

/// Derived provider exposing the current font combination ID string.
final fontCombinationIdProvider = Provider<String>((ref) {
  ref.watch(fontCombinationProvider);
  return ref.read(fontCombinationProvider.notifier).fontCombinationId;
});

/// Initial font combination ID, overridden at app startup from storage.
final initialFontCombinationIdProvider = Provider<String>(
  (ref) => kFontCombinationDefault,
);

/// Manages the selected font combination state with persistence.
class FontCombinationNotifier extends Notifier<FontCombination> {
  LocalStorageService get _storage => ref.read(localStorageServiceProvider);

  String _fontCombinationId = kFontCombinationDefault;

  @override
  FontCombination build() {
    _fontCombinationId = ref.read(initialFontCombinationIdProvider);
    return FontCombination.fromId(_fontCombinationId);
  }

  /// The current font combination ID string.
  String get fontCombinationId => _fontCombinationId;

  /// Set the font combination by ID and persist to storage.
  Future<void> setFontCombination(String id) async {
    _fontCombinationId = id;
    state = FontCombination.fromId(id);
    await _storage.saveString(AppConstants.fontCombinationKey, id);
  }

  /// Load the saved font combination from storage (called during app init).
  Future<void> loadSavedFontCombination() async {
    final saved = await _storage.getString(AppConstants.fontCombinationKey);
    _fontCombinationId = saved ?? kFontCombinationDefault;
    state = FontCombination.fromId(_fontCombinationId);
  }
}
