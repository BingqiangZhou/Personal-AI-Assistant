import 'package:flutter/material.dart';

import 'package:personal_ai_assistant/core/constants/app_spacing.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations_extension.dart';
import 'package:personal_ai_assistant/core/widgets/adaptive/adaptive_sliver_app_bar.dart';
import 'package:personal_ai_assistant/core/widgets/custom_adaptive_navigation.dart'
    show ResponsiveContainer;

/// Static Privacy Policy page.
class PrivacyPage extends StatelessWidget {
  const PrivacyPage({super.key});

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final theme = Theme.of(context);

    return Scaffold(
      backgroundColor: Colors.transparent,
      body: Material(
        color: Colors.transparent,
        child: ResponsiveContainer(
          maxWidth: 720,
          alignment: Alignment.topCenter,
          child: CustomScrollView(
            slivers: [
              AdaptiveSliverAppBar(
                title: l10n.privacy_policy_title,
              ),
              SliverToBoxAdapter(
                  child: SizedBox(height: context.spacing.smMd)),
              SliverFillRemaining(
                hasScrollBody: false,
                child: SingleChildScrollView(
                  padding: EdgeInsets.symmetric(
                    horizontal: context.spacing.mdLg,
                    vertical: context.spacing.sm,
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        l10n.privacy_policy_title,
                        style: theme.textTheme.headlineSmall?.copyWith(
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      SizedBox(height: context.spacing.sm),
                      Text(
                        l10n.privacy_policy_last_updated,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                      SizedBox(height: context.spacing.lg),
                      _buildSection(
                        context,
                        title: l10n.privacy_section_intro,
                        body: l10n.privacy_section_intro_body,
                      ),
                      _buildSection(
                        context,
                        title: l10n.privacy_section_collection,
                        body: l10n.privacy_section_collection_body,
                      ),
                      _buildSection(
                        context,
                        title: l10n.privacy_section_usage,
                        body: l10n.privacy_section_usage_body,
                      ),
                      _buildSection(
                        context,
                        title: l10n.privacy_section_storage,
                        body: l10n.privacy_section_storage_body,
                      ),
                      _buildSection(
                        context,
                        title: l10n.privacy_section_sharing,
                        body: l10n.privacy_section_sharing_body,
                      ),
                      _buildSection(
                        context,
                        title: l10n.privacy_section_rights,
                        body: l10n.privacy_section_rights_body,
                      ),
                      _buildSection(
                        context,
                        title: l10n.privacy_section_children,
                        body: l10n.privacy_section_children_body,
                      ),
                      _buildSection(
                        context,
                        title: l10n.privacy_section_changes,
                        body: l10n.privacy_section_changes_body,
                      ),
                      _buildSection(
                        context,
                        title: l10n.privacy_section_contact,
                        body: l10n.privacy_section_contact_body,
                      ),
                      SizedBox(height: context.spacing.xl),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildSection(
    BuildContext context, {
    required String title,
    required String body,
  }) {
    final theme = Theme.of(context);
    return Padding(
      padding: EdgeInsets.only(bottom: context.spacing.mdLg),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: theme.textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
          SizedBox(height: context.spacing.sm),
          Text(
            body,
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
              height: 1.6,
            ),
          ),
        ],
      ),
    );
  }
}
