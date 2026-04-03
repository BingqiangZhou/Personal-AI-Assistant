/// A font combination pairing a heading font with a body font.
///
/// Each combination is identified by a stable [id] string for persistence.
/// The [all] registry contains all available combinations, and [fromId]
/// provides safe lookup with fallback to the default.
class FontCombination {
  const FontCombination({
    required this.id,
    required this.displayName,
    required this.headingFontFamily,
    required this.bodyFontFamily,
  });

  /// Stable key used for persistence (e.g. 'space_grotesk_inter').
  final String id;

  /// Human-readable name for display (e.g. 'Space Grotesk + Inter').
  final String displayName;

  /// Google Fonts API name for the heading font.
  final String headingFontFamily;

  /// Google Fonts API name for the body font.
  final String bodyFontFamily;

  // ============================================================
  // REGISTRY
  // ============================================================

  /// All available font combinations.
  static const List<FontCombination> all = [
    FontCombination(
      id: 'space_grotesk_inter',
      displayName: 'Space Grotesk + Inter',
      headingFontFamily: 'SpaceGrotesk',
      bodyFontFamily: 'Inter',
    ),
    FontCombination(
      id: 'sora_inter',
      displayName: 'Sora + Inter',
      headingFontFamily: 'Sora',
      bodyFontFamily: 'Inter',
    ),
    FontCombination(
      id: 'plus_jakarta_sans',
      displayName: 'Plus Jakarta Sans',
      headingFontFamily: 'PlusJakartaSans',
      bodyFontFamily: 'PlusJakartaSans',
    ),
    FontCombination(
      id: 'urbanist_manrope',
      displayName: 'Urbanist + Manrope',
      headingFontFamily: 'Urbanist',
      bodyFontFamily: 'Manrope',
    ),
    FontCombination(
      id: 'onest',
      displayName: 'Onest',
      headingFontFamily: 'Onest',
      bodyFontFamily: 'Onest',
    ),
    FontCombination(
      id: 'figtree_source_sans_3',
      displayName: 'Figtree + Source Sans 3',
      headingFontFamily: 'Figtree',
      bodyFontFamily: 'SourceSans3',
    ),
    FontCombination(
      id: 'outfit_literata',
      displayName: 'Outfit + Literata',
      headingFontFamily: 'Outfit',
      bodyFontFamily: 'Literata',
    ),
    FontCombination(
      id: 'dm_sans_dm_serif_display',
      displayName: 'DM Sans + DM Serif Display',
      headingFontFamily: 'DMSans',
      bodyFontFamily: 'DMSerifDisplay',
    ),
    FontCombination(
      id: 'nunito_open_sans',
      displayName: 'Nunito + Open Sans',
      headingFontFamily: 'Nunito',
      bodyFontFamily: 'OpenSans',
    ),
    FontCombination(
      id: 'poppins_lato',
      displayName: 'Poppins + Lato',
      headingFontFamily: 'Poppins',
      bodyFontFamily: 'Lato',
    ),
    FontCombination(
      id: 'montserrat_merriweather',
      displayName: 'Montserrat + Merriweather',
      headingFontFamily: 'Montserrat',
      bodyFontFamily: 'Merriweather',
    ),
    FontCombination(
      id: 'playfair_display_source_sans_3',
      displayName: 'Playfair Display + Source Sans 3',
      headingFontFamily: 'PlayfairDisplay',
      bodyFontFamily: 'SourceSans3',
    ),
    FontCombination(
      id: 'raleway_roboto',
      displayName: 'Raleway + Roboto',
      headingFontFamily: 'Raleway',
      bodyFontFamily: 'Roboto',
    ),
    FontCombination(
      id: 'lexend_inter',
      displayName: 'Lexend + Inter',
      headingFontFamily: 'Lexend',
      bodyFontFamily: 'Inter',
    ),
    FontCombination(
      id: 'ibm_plex_sans_serif',
      displayName: 'IBM Plex Sans + Serif',
      headingFontFamily: 'IBMPlexSans',
      bodyFontFamily: 'IBMPlexSerif',
    ),
    FontCombination(
      id: 'fraunces_work_sans',
      displayName: 'Fraunces + Work Sans',
      headingFontFamily: 'Fraunces',
      bodyFontFamily: 'WorkSans',
    ),
  ];

  /// The default (current production) font combination.
  static const FontCombination defaultCombination = FontCombination(
    id: 'outfit_literata',
    displayName: 'Outfit + Literata',
    headingFontFamily: 'Outfit',
    bodyFontFamily: 'Literata',
  );

  /// Look up a combination by [id], falling back to [defaultCombination].
  static FontCombination fromId(String? id) {
    if (id == null) return defaultCombination;
    return all.firstWhere(
      (c) => c.id == id,
      orElse: () => defaultCombination,
    );
  }

  @override
  String toString() => 'FontCombination($displayName)';
}
