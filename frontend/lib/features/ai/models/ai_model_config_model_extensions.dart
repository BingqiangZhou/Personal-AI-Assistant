import 'package:flutter/material.dart';
import '../../../../core/localization/app_localizations.dart';
import 'ai_model_config_model.dart';

/// Extension on [AIModelType] to provide localized model type names
extension AIModelTypeLocalization on AIModelType {
  /// Get the localized display name for this model type
  String getLocalizedDisplayName(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    switch (this) {
      case AIModelType.transcription:
        return l10n.ai_model_type_transcription;
      case AIModelType.textGeneration:
        return l10n.ai_model_type_text_generation;
    }
  }
}

/// Extension on [AIModelConfigModel] to provide localized model information
extension AIModelConfigModelLocalization on AIModelConfigModel {
  /// Get the localized display name for this model's type
  String getLocalizedModelTypeDisplayName(BuildContext context) {
    return modelType.getLocalizedDisplayName(context);
  }

  /// Get the localized provider name
  String getLocalizedProviderName(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    switch (provider) {
      case 'anthropic':
        return 'Anthropic';
      case 'azure':
        return l10n.ai_provider_azure_openai;
      default:
        return provider.toUpperCase();
    }
  }
}
