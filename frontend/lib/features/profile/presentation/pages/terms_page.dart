import 'package:flutter/material.dart';

import 'package:personal_ai_assistant/core/constants/app_spacing.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations_extension.dart';
import 'package:personal_ai_assistant/core/widgets/adaptive/adaptive_sliver_app_bar.dart';
import 'package:personal_ai_assistant/core/widgets/custom_adaptive_navigation.dart'
    show ResponsiveContainer;

/// Static Terms of Service page.
class TermsPage extends StatelessWidget {
  const TermsPage({super.key});

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
                title: l10n.terms_of_service_title,
              ),
              SliverToBoxAdapter(
                  child: SizedBox(height: context.spacing.smMd)),
              SliverToBoxAdapter(
                child: Padding(
                  padding: EdgeInsets.symmetric(
                    horizontal: context.spacing.mdLg,
                    vertical: context.spacing.sm,
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        l10n.terms_of_service_title,
                        style: theme.textTheme.headlineSmall?.copyWith(
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      SizedBox(height: context.spacing.sm),
                      Text(
                        l10n.terms_of_service_last_updated,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                      SizedBox(height: context.spacing.lg),
                      _buildSection(
                        context,
                        title: l10n.terms_section_acceptance,
                        body: l10n.terms_section_acceptance_body,
                      ),
                      _buildSection(
                        context,
                        title: l10n.terms_section_use,
                        body: l10n.terms_section_use_body,
                      ),
                      _buildSection(
                        context,
                        title: l10n.terms_section_ip,
                        body: l10n.terms_section_ip_body,
                      ),
                      _buildSection(
                        context,
                        title: l10n.terms_section_liability,
                        body: l10n.terms_section_liability_body,
                      ),
                      _buildSection(
                        context,
                        title: l10n.terms_section_changes,
                        body: l10n.terms_section_changes_body,
                      ),
                      _buildSection(
                        context,
                        title: l10n.terms_section_governing_law,
                        body: l10n.terms_section_governing_law_body,
                      ),
                      _buildSection(
                        context,
                        title: l10n.terms_section_contact,
                        body: l10n.terms_section_contact_body,
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
