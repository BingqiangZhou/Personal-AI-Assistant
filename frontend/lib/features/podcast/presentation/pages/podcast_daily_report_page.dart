import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../../../../core/widgets/top_floating_notice.dart';
import '../../../auth/presentation/providers/auth_provider.dart';
import '../providers/podcast_providers.dart';

class PodcastDailyReportPage extends ConsumerStatefulWidget {
  const PodcastDailyReportPage({super.key, this.initialDate, this.source});

  final DateTime? initialDate;
  final String? source;

  @override
  ConsumerState<PodcastDailyReportPage> createState() =>
      _PodcastDailyReportPageState();
}

class _PodcastDailyReportPageState
    extends ConsumerState<PodcastDailyReportPage> {
  bool _isGeneratingDailyReport = false;
  final Set<int> _expandedReportItems = <int>{};

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final targetDate = _resolveInitialDate(widget.initialDate);
      ref.read(selectedDailyReportDateProvider.notifier).setDate(targetDate);

      final isAuthenticated = ref.read(authProvider).isAuthenticated;
      if (!isAuthenticated) {
        return;
      }

      ref
          .read(dailyReportProvider.notifier)
          .load(date: targetDate, forceRefresh: true);
      ref.read(dailyReportDatesProvider.notifier).load(forceRefresh: true);
    });
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return Scaffold(
      key: const Key('daily_report_page'),
      appBar: AppBar(title: Text(l10n.podcast_daily_report_title)),
      body: ResponsiveContainer(
        child: Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: _buildDailyReportPanel(context),
        ),
      ),
    );
  }

  Widget _buildDailyReportPanel(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final reportAsync = ref.watch(dailyReportProvider);
    final selectedDate = ref.watch(selectedDailyReportDateProvider);
    final report = reportAsync.value;
    final maxReportItemsViewportHeight =
        (MediaQuery.sizeOf(context).height * 0.62).clamp(220.0, 560.0);

    Widget buildHeader({
      DateTime? reportDate,
      int totalItems = 0,
      DateTime? generatedAt,
      bool showMeta = false,
    }) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  l10n.podcast_daily_report_title,
                  style: theme.textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
              Flexible(
                child: TextButton.icon(
                  key: const Key('daily_report_date_selector_button'),
                  onPressed: () => _showDailyReportDateSelector(
                    context,
                    fallbackDate: reportDate ?? selectedDate,
                  ),
                  icon: const Icon(Icons.event_outlined, size: 18),
                  label: Text(
                    reportDate == null
                        ? l10n.podcast_daily_report_dates
                        : _formatDate(reportDate),
                    overflow: TextOverflow.ellipsis,
                    maxLines: 1,
                  ),
                ),
              ),
            ],
          ),
          if (showMeta)
            Text(
              '${l10n.podcast_daily_report_items(totalItems)} · ${l10n.podcast_daily_report_generated_prefix} ${_formatTime(generatedAt)}',
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
        ],
      );
    }

    Widget buildSurface(Widget child) {
      return Material(
        color: theme.colorScheme.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: BorderSide(
            color: theme.colorScheme.outlineVariant.withValues(alpha: 0.35),
          ),
        ),
        child: Padding(padding: const EdgeInsets.all(12), child: child),
      );
    }

    if (reportAsync.isLoading && report == null) {
      return buildSurface(
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            buildHeader(reportDate: selectedDate),
            const SizedBox(height: 8),
            Row(
              children: [
                SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: theme.colorScheme.primary,
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    l10n.podcast_daily_report_loading,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
          ],
        ),
      );
    }

    if (reportAsync.hasError && report == null) {
      return buildSurface(
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            buildHeader(reportDate: selectedDate),
            const SizedBox(height: 8),
            Text(
              l10n.podcast_failed_to_load_feed,
              style: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.error,
              ),
            ),
            const SizedBox(height: 8),
            FilledButton.tonal(
              onPressed: () {
                ref
                    .read(dailyReportProvider.notifier)
                    .load(date: selectedDate, forceRefresh: true);
                ref
                    .read(dailyReportDatesProvider.notifier)
                    .load(forceRefresh: true);
              },
              child: Text(l10n.podcast_retry),
            ),
          ],
        ),
      );
    }

    final currentReport = report;
    if (currentReport == null || !currentReport.available) {
      final targetDate = selectedDate ?? currentReport?.reportDate;
      final shouldShowRefreshButton = targetDate != null;
      return buildSurface(
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            buildHeader(reportDate: selectedDate),
            const SizedBox(height: 8),
            Text(
              l10n.podcast_daily_report_empty,
              style: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            if (shouldShowRefreshButton) ...[
              const SizedBox(height: 8),
              FilledButton.tonalIcon(
                key: const Key('daily_report_regenerate_button'),
                onPressed: _isGeneratingDailyReport
                    ? null
                    : () => _generateDailyReportForSelectedDate(
                        targetDate,
                        rebuild: true,
                      ),
                icon: const Icon(Icons.refresh, size: 18),
                label: Text(
                  _isGeneratingDailyReport
                      ? l10n.podcast_daily_report_loading
                      : l10n.refresh,
                ),
              ),
            ],
          ],
        ),
      );
    }

    return buildSurface(
      Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          buildHeader(
            reportDate: currentReport.reportDate,
            totalItems: currentReport.totalItems,
            generatedAt: currentReport.generatedAt,
            showMeta: true,
          ),
          const SizedBox(height: 8),
          Align(
            alignment: Alignment.centerLeft,
            child: FilledButton.tonalIcon(
              key: const Key('daily_report_regenerate_button'),
              onPressed: _isGeneratingDailyReport
                  ? null
                  : () => _generateDailyReportForSelectedDate(
                      currentReport.reportDate ?? selectedDate,
                      rebuild: true,
                    ),
              icon: const Icon(Icons.refresh, size: 18),
              label: Text(
                _isGeneratingDailyReport
                    ? l10n.podcast_daily_report_loading
                    : l10n.refresh,
              ),
            ),
          ),
          const SizedBox(height: 10),
          if (currentReport.items.isEmpty)
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  l10n.podcast_daily_report_empty,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            )
          else
            SizedBox(
              height: maxReportItemsViewportHeight,
              child: Scrollbar(
                thumbVisibility: currentReport.items.length > 4,
                child: ListView.separated(
                  key: const Key('daily_report_items_scroll'),
                  primary: false,
                  padding: EdgeInsets.zero,
                  itemCount: currentReport.items.length,
                  separatorBuilder: (_, _index) => const SizedBox(height: 8),
                  itemBuilder: (itemContext, index) {
                    final item = currentReport.items[index];
                    final isExpanded = _expandedReportItems.contains(
                      item.episodeId,
                    );
                    final metaLine =
                        '${item.episodeTitle} · ${item.subscriptionTitle ?? l10n.podcast_default_podcast}';
                    return InkWell(
                      key: Key('daily_report_item_${item.episodeId}'),
                      onTap: () {
                        context.push(
                          '/podcast/episode/detail/${item.episodeId}',
                        );
                      },
                      borderRadius: BorderRadius.circular(10),
                      child: Padding(
                        padding: const EdgeInsets.all(8),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              item.oneLineSummary,
                              maxLines: isExpanded ? null : 2,
                              overflow: isExpanded
                                  ? TextOverflow.visible
                                  : TextOverflow.ellipsis,
                              style: theme.textTheme.titleSmall?.copyWith(
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                            Align(
                              alignment: Alignment.centerLeft,
                              child: TextButton(
                                key: Key(
                                  'daily_report_item_toggle_${item.episodeId}',
                                ),
                                onPressed: () =>
                                    _toggleItemExpanded(item.episodeId),
                                style: TextButton.styleFrom(
                                  visualDensity: VisualDensity.compact,
                                  padding: EdgeInsets.zero,
                                  minimumSize: const Size(0, 0),
                                  tapTargetSize:
                                      MaterialTapTargetSize.shrinkWrap,
                                ),
                                child: Text(
                                  isExpanded
                                      ? l10n.podcast_player_collapse
                                      : l10n.podcast_player_expand,
                                ),
                              ),
                            ),
                            const SizedBox(height: 6),
                            Text(
                              metaLine,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: theme.textTheme.labelMedium?.copyWith(
                                color: theme.colorScheme.onSurfaceVariant,
                              ),
                            ),
                          ],
                        ),
                      ),
                    );
                  },
                ),
              ),
            ),
        ],
      ),
    );
  }

  void _toggleItemExpanded(int episodeId) {
    setState(() {
      if (_expandedReportItems.contains(episodeId)) {
        _expandedReportItems.remove(episodeId);
      } else {
        _expandedReportItems.add(episodeId);
      }
    });
  }

  Future<void> _showDailyReportDateSelector(
    BuildContext context, {
    required DateTime? fallbackDate,
  }) async {
    final now = _toDateOnly(DateTime.now());
    final previousDay = now.subtract(const Duration(days: 1));
    final selectedDate = ref.read(selectedDailyReportDateProvider);
    DateTime initialDate = _toDateOnly(
      selectedDate ?? fallbackDate ?? previousDay,
    );
    if (initialDate.isAfter(now)) {
      initialDate = now;
    }

    final pickedDate = await showDatePicker(
      context: context,
      initialDate: initialDate,
      firstDate: DateTime(2000, 1, 1),
      lastDate: now,
    );
    if (pickedDate == null) {
      return;
    }

    final normalized = _toDateOnly(pickedDate);
    ref.read(selectedDailyReportDateProvider.notifier).setDate(normalized);
    await ref
        .read(dailyReportProvider.notifier)
        .load(date: normalized, forceRefresh: true);
  }

  Future<void> _generateDailyReportForSelectedDate(
    DateTime? selectedDate, {
    bool rebuild = false,
  }) async {
    if (selectedDate == null) {
      return;
    }
    setState(() {
      _isGeneratingDailyReport = true;
    });

    try {
      final generated = await ref
          .read(dailyReportProvider.notifier)
          .generate(date: selectedDate, rebuild: rebuild);
      if (!mounted) {
        return;
      }

      if (generated != null && generated.available) {
        final l10n = AppLocalizations.of(context)!;
        showTopFloatingNotice(
          context,
          message: l10n.podcast_daily_report_generate_success,
          extraTopOffset: 64,
        );
      } else {
        final l10n = AppLocalizations.of(context)!;
        showTopFloatingNotice(
          context,
          message: l10n.podcast_daily_report_generate_failed,
          isError: true,
          extraTopOffset: 64,
        );
      }
    } catch (error) {
      if (mounted) {
        final l10n = AppLocalizations.of(context)!;
        final errorMessage = error.toString().trim();
        showTopFloatingNotice(
          context,
          message: errorMessage.isEmpty
              ? l10n.podcast_daily_report_generate_failed
              : '${l10n.podcast_daily_report_generate_failed}: $errorMessage',
          isError: true,
          extraTopOffset: 64,
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _isGeneratingDailyReport = false;
        });
      }
    }
  }

  DateTime _resolveInitialDate(DateTime? rawValue) {
    final now = _toDateOnly(DateTime.now());
    final minimum = DateTime(2000, 1, 1);
    final fallback = now.subtract(const Duration(days: 1));
    if (rawValue == null) {
      return fallback;
    }

    final normalized = _toDateOnly(rawValue);
    if (normalized.isAfter(now)) {
      return now;
    }
    if (normalized.isBefore(minimum)) {
      return minimum;
    }
    return normalized;
  }

  DateTime _toDateOnly(DateTime value) {
    final local = value.isUtc ? value.toLocal() : value;
    return DateTime(local.year, local.month, local.day);
  }
}

String _formatDate(DateTime date) {
  final localDate = date.isUtc ? date.toLocal() : date;
  return '${localDate.year}-${localDate.month.toString().padLeft(2, '0')}-${localDate.day.toString().padLeft(2, '0')}';
}

String _formatTime(DateTime? dateTime) {
  if (dateTime == null) {
    return '--:--';
  }
  final local = dateTime.isUtc ? dateTime.toLocal() : dateTime;
  return '${local.hour.toString().padLeft(2, '0')}:${local.minute.toString().padLeft(2, '0')}';
}
