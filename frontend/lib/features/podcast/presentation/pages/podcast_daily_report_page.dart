import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:table_calendar/table_calendar.dart';

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
  static final RegExp _summaryTrailingDividerRegExp = RegExp(
    r'(?:\s*---\s*)+$',
  );
  late DateTime _focusedCalendarDay;

  @override
  void initState() {
    super.initState();
    final targetDate = _resolveInitialDate(widget.initialDate);
    _focusedCalendarDay = targetDate;

    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(selectedDailyReportDateProvider.notifier).setDate(targetDate);

      final isAuthenticated = ref.read(authProvider).isAuthenticated;
      if (!isAuthenticated) {
        return;
      }

      unawaited(_loadInitialDailyReportData(targetDate));
    });
  }

  Future<void> _loadInitialDailyReportData(DateTime targetDate) async {
    await Future.wait([
      ref
          .read(dailyReportProvider.notifier)
          .load(date: targetDate, forceRefresh: true),
      ref.read(dailyReportDatesProvider.notifier).load(forceRefresh: true),
    ]);
    await ref
        .read(dailyReportDatesProvider.notifier)
        .ensureMonthCoverage(targetDate);
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return Scaffold(
      key: const Key('daily_report_page'),
      appBar: AppBar(
        centerTitle: false,
        title: Text(l10n.podcast_daily_report_title),
      ),
      body: ResponsiveContainer(
        maxWidth: 1480,
        alignment: Alignment.topCenter,
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
    final reportDatesAsync = ref.watch(dailyReportDatesProvider);
    final selectedDate = ref.watch(selectedDailyReportDateProvider);
    final report = reportAsync.value;
    final reportDateKeys = <String>{
      for (final item in reportDatesAsync.value?.dates ?? const [])
        _formatDate(item.reportDate),
    };
    final now = _toDateOnly(DateTime.now());
    final maxReportItemsViewportHeight =
        (MediaQuery.sizeOf(context).height * 0.46).clamp(180.0, 420.0);

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

    Widget buildHeader({
      DateTime? reportDate,
      int totalItems = 0,
      DateTime? generatedAt,
      bool showMeta = false,
      Widget? action,
    }) {
      final headerDate = reportDate ?? selectedDate;
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Flexible(
                child: Text(
                  l10n.podcast_daily_report_title,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
              if (action != null) ...[const SizedBox(width: 8), action],
              const Spacer(),
              const Icon(Icons.event_outlined, size: 18),
              const SizedBox(width: 6),
              Text(
                headerDate == null ? '--' : _formatDate(headerDate),
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          if (showMeta)
            Text(
              '${l10n.podcast_daily_report_items(totalItems)} | ${l10n.podcast_daily_report_generated_prefix} ${_formatTime(generatedAt)}',
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
        ],
      );
    }

    Widget buildRegenerateButton(DateTime? targetDate) {
      return FilledButton.tonalIcon(
        key: const Key('daily_report_regenerate_button'),
        onPressed: _isGeneratingDailyReport || targetDate == null
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
      );
    }

    final displayFocusedDay = _focusedCalendarDay.isAfter(now)
        ? now
        : _focusedCalendarDay;

    final calendarCard = buildSurface(
      Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            l10n.podcast_daily_report_dates,
            style: theme.textTheme.titleSmall?.copyWith(
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 8),
          SizedBox(
            key: const Key('daily_report_calendar'),
            child: TableCalendar<bool>(
              firstDay: DateTime(2000, 1, 1),
              lastDay: now,
              focusedDay: displayFocusedDay,
              calendarFormat: CalendarFormat.month,
              availableCalendarFormats: const {CalendarFormat.month: 'Month'},
              selectedDayPredicate: (day) => _isSameDate(day, selectedDate),
              enabledDayPredicate: (day) {
                final normalizedDay = _toDateOnly(day);
                return !normalizedDay.isAfter(now);
              },
              eventLoader: (day) {
                final hasReport = reportDateKeys.contains(_formatDate(day));
                return hasReport ? const [true] : const [];
              },
              onDaySelected: (pickedDay, focusedDay) {
                unawaited(
                  _handleCalendarDaySelected(
                    pickedDay: pickedDay,
                    focusedDay: focusedDay,
                  ),
                );
              },
              onPageChanged: (focusedDay) {
                final normalizedFocused = _toDateOnly(focusedDay);
                setState(() {
                  _focusedCalendarDay = normalizedFocused;
                });
                unawaited(
                  ref
                      .read(dailyReportDatesProvider.notifier)
                      .ensureMonthCoverage(normalizedFocused),
                );
              },
              calendarBuilders: CalendarBuilders<bool>(
                defaultBuilder: (context, day, _) => _buildCalendarDayCell(
                  context,
                  day,
                  selectedDate: selectedDate,
                ),
                outsideBuilder: (context, day, _) => _buildCalendarDayCell(
                  context,
                  day,
                  selectedDate: selectedDate,
                  isOutside: true,
                ),
                disabledBuilder: (context, day, _) => _buildCalendarDayCell(
                  context,
                  day,
                  selectedDate: selectedDate,
                  isDisabled: true,
                ),
                todayBuilder: (context, day, _) => _buildCalendarDayCell(
                  context,
                  day,
                  selectedDate: selectedDate,
                  isToday: true,
                ),
                selectedBuilder: (context, day, _) => _buildCalendarDayCell(
                  context,
                  day,
                  selectedDate: selectedDate,
                  isSelected: true,
                ),
                markerBuilder: (context, day, events) {
                  if (events.isEmpty) {
                    return null;
                  }
                  final isSelected = _isSameDate(day, selectedDate);
                  final markerColor = isSelected
                      ? theme.colorScheme.onPrimary
                      : theme.colorScheme.primary;
                  return Positioned(
                    key: Key(
                      'daily_report_calendar_marker_${_formatDate(day)}',
                    ),
                    bottom: 4,
                    child: Container(
                      width: 5,
                      height: 5,
                      decoration: BoxDecoration(
                        color: markerColor,
                        shape: BoxShape.circle,
                      ),
                    ),
                  );
                },
              ),
            ),
          ),
          if (reportDatesAsync.isLoading && reportDatesAsync.value == null) ...[
            const SizedBox(height: 8),
            Row(
              children: [
                SizedBox(
                  width: 14,
                  height: 14,
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
                    style: theme.textTheme.bodySmall,
                  ),
                ),
              ],
            ),
          ],
        ],
      ),
    );

    Widget reportCard;
    if (reportAsync.isLoading && report == null) {
      reportCard = buildSurface(
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
    } else if (reportAsync.hasError && report == null) {
      reportCard = buildSurface(
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
    } else {
      final currentReport = report;
      if (currentReport == null || !currentReport.available) {
        final targetDate = selectedDate ?? currentReport?.reportDate;
        reportCard = buildSurface(
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              buildHeader(
                reportDate: selectedDate,
                action: buildRegenerateButton(targetDate),
              ),
              const SizedBox(height: 8),
              Text(
                l10n.podcast_daily_report_empty,
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ],
          ),
        );
      } else {
        reportCard = buildSurface(
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              buildHeader(
                reportDate: currentReport.reportDate,
                totalItems: currentReport.totalItems,
                generatedAt: currentReport.generatedAt,
                showMeta: true,
                action: buildRegenerateButton(
                  currentReport.reportDate ?? selectedDate,
                ),
              ),
              const SizedBox(height: 10),
              if (currentReport.items.isEmpty)
                Text(
                  l10n.podcast_daily_report_empty,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
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
                      separatorBuilder: (_, _index) =>
                          const SizedBox(height: 8),
                      itemBuilder: (itemContext, index) {
                        final item = currentReport.items[index];
                        final metaLine =
                            '${item.episodeTitle} | ${item.subscriptionTitle ?? l10n.podcast_default_podcast}';
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
                                  _sanitizeOneLineSummary(item.oneLineSummary),
                                  style: theme.textTheme.titleSmall?.copyWith(
                                    fontWeight: FontWeight.w700,
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
    }

    return LayoutBuilder(
      builder: (context, constraints) {
        final isWideLayout = constraints.maxWidth >= 1180;
        if (isWideLayout) {
          return SingleChildScrollView(
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(flex: 5, child: calendarCard),
                const SizedBox(width: 14),
                Expanded(flex: 7, child: reportCard),
              ],
            ),
          );
        }

        return SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [calendarCard, const SizedBox(height: 12), reportCard],
          ),
        );
      },
    );
  }

  Widget _buildCalendarDayCell(
    BuildContext context,
    DateTime day, {
    required DateTime? selectedDate,
    bool isSelected = false,
    bool isToday = false,
    bool isOutside = false,
    bool isDisabled = false,
  }) {
    final theme = Theme.of(context);
    final normalizedDay = _toDateOnly(day);
    final selected = isSelected || _isSameDate(normalizedDay, selectedDate);
    Color textColor = theme.colorScheme.onSurface;
    if (selected) {
      textColor = theme.colorScheme.onPrimary;
    } else if (isOutside || isDisabled) {
      textColor = theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.6);
    } else if (isToday) {
      textColor = theme.colorScheme.primary;
    }

    return Center(
      child: Container(
        key: Key('daily_report_calendar_day_${_formatDate(normalizedDay)}'),
        width: 36,
        height: 36,
        alignment: Alignment.center,
        decoration: BoxDecoration(
          color: selected ? theme.colorScheme.primary : Colors.transparent,
          shape: BoxShape.circle,
          border: isToday && !selected
              ? Border.all(color: theme.colorScheme.primary)
              : null,
        ),
        child: Text(
          '${normalizedDay.day}',
          style: theme.textTheme.bodyMedium?.copyWith(
            color: textColor,
            fontWeight: selected ? FontWeight.w700 : FontWeight.w500,
          ),
        ),
      ),
    );
  }

  Future<void> _handleCalendarDaySelected({
    required DateTime pickedDay,
    required DateTime focusedDay,
  }) async {
    final normalizedSelected = _toDateOnly(pickedDay);
    final normalizedFocused = _toDateOnly(focusedDay);
    if (mounted) {
      setState(() {
        _focusedCalendarDay = normalizedFocused;
      });
    }
    ref
        .read(selectedDailyReportDateProvider.notifier)
        .setDate(normalizedSelected);
    await ref
        .read(dailyReportProvider.notifier)
        .load(date: normalizedSelected, forceRefresh: true);
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

  bool _isSameDate(DateTime? left, DateTime? right) {
    if (left == null || right == null) {
      return false;
    }
    final l = _toDateOnly(left);
    final r = _toDateOnly(right);
    return l.year == r.year && l.month == r.month && l.day == r.day;
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

  String _sanitizeOneLineSummary(String rawSummary) {
    final normalized = rawSummary.trim();
    if (normalized.isEmpty) {
      return normalized;
    }
    return normalized.replaceAll(_summaryTrailingDividerRegExp, '').trim();
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
