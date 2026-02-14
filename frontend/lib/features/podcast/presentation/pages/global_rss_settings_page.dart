import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../../core/localization/app_localizations.dart';
import '../../../../core/widgets/top_floating_notice.dart';
import '../../data/models/schedule_config_model.dart';
import '../providers/global_schedule_provider.dart';

class GlobalRSSSettingsPage extends ConsumerStatefulWidget {
  const GlobalRSSSettingsPage({super.key});

  @override
  ConsumerState<GlobalRSSSettingsPage> createState() =>
      _GlobalRSSSettingsPageState();
}

class _GlobalRSSSettingsPageState extends ConsumerState<GlobalRSSSettingsPage> {
  UpdateFrequency? _selectedFrequency = UpdateFrequency.hourly;
  TimeOfDay? _selectedTime;
  int? _selectedDayOfWeek;
  bool _isSaving = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(globalScheduleProvider.notifier).loadAllSchedules();
    });
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(globalScheduleProvider);
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context);

    return Scaffold(
      appBar: AppBar(
        title: Text(l10n!.podcast_global_rss_settings_title),
        actions: [
          if (state.isLoading)
            const Padding(
              padding: EdgeInsets.all(16),
              child: SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
            )
          else
            IconButton(
              icon: const Icon(Icons.refresh),
              onPressed: () {
                ref.read(globalScheduleProvider.notifier).loadAllSchedules();
              },
            ),
        ],
      ),
      body: _buildBody(state, theme),
    );
  }

  Widget _buildBody(GlobalScheduleState state, ThemeData theme) {
    if (state.isLoading && state.schedules.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }

    if (state.error != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 48, color: Colors.red),
            const SizedBox(height: 16),
            Text(
              AppLocalizations.of(context)!.global_rss_failed_load,
              style: theme.textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            Text(
              state.error!,
              style: theme.textTheme.bodyMedium,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: () {
                ref.read(globalScheduleProvider.notifier).loadAllSchedules();
              },
              child: Text(AppLocalizations.of(context)!.global_rss_retry),
            ),
          ],
        ),
      );
    }

    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildGlobalSettingsCard(theme, state.schedules.length),
          const SizedBox(height: 24),
          Text(
            AppLocalizations.of(
              context,
            )!.global_rss_affected_count(state.schedules.length),
            style: theme.textTheme.titleLarge?.copyWith(
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 16),
          if (state.schedules.isEmpty)
            Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Icon(Icons.podcasts, size: 64, color: Colors.grey),
                  const SizedBox(height: 16),
                  Text(
                    AppLocalizations.of(context)!.global_rss_no_subscriptions,
                    style: const TextStyle(fontSize: 18, color: Colors.grey),
                  ),
                ],
              ),
            )
          else
            _buildSubscriptionsList(state.schedules, theme),
        ],
      ),
    );
  }

  Widget _buildGlobalSettingsCard(ThemeData theme, int subscriptionCount) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.settings_suggest,
                  color: theme.colorScheme.primary,
                  size: 28,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        AppLocalizations.of(context)!.global_rss_schedule_title,
                        style: theme.textTheme.titleLarge?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        AppLocalizations.of(
                          context,
                        )!.global_rss_apply_desc(subscriptionCount),
                        style: theme.textTheme.bodyMedium?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 24),
            Text(
              AppLocalizations.of(context)!.global_rss_update_frequency,
              style: theme.textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 12),
            SegmentedButton<UpdateFrequency>(
              segments: [
                ButtonSegment(
                  value: UpdateFrequency.hourly,
                  label: Text(AppLocalizations.of(context)!.global_rss_hourly),
                  icon: const Icon(Icons.access_time_filled),
                ),
                ButtonSegment(
                  value: UpdateFrequency.daily,
                  label: Text(AppLocalizations.of(context)!.global_rss_daily),
                  icon: const Icon(Icons.today),
                ),
                ButtonSegment(
                  value: UpdateFrequency.weekly,
                  label: Text(AppLocalizations.of(context)!.global_rss_weekly),
                  icon: const Icon(Icons.calendar_view_week),
                ),
              ],
              selected: {_selectedFrequency ?? UpdateFrequency.hourly},
              onSelectionChanged: (Set<UpdateFrequency> selected) {
                setState(() {
                  _selectedFrequency = selected.first;
                  if (_selectedFrequency == UpdateFrequency.hourly) {
                    _selectedTime = null;
                    _selectedDayOfWeek = null;
                  }
                });
              },
            ),
            if (_selectedFrequency == UpdateFrequency.daily ||
                _selectedFrequency == UpdateFrequency.weekly) ...[
              const SizedBox(height: 20),
              Text(
                AppLocalizations.of(context)!.global_rss_update_time,
                style: theme.textTheme.titleMedium?.copyWith(
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 8),
              InkWell(
                onTap: _pickTime,
                child: InputDecorator(
                  decoration: InputDecoration(
                    border: const OutlineInputBorder(),
                    filled: true,
                    suffixIcon: const Icon(Icons.access_time),
                    hintText: AppLocalizations.of(
                      context,
                    )!.global_rss_select_time,
                  ),
                  child: Text(
                    _selectedTime?.format(context) ??
                        AppLocalizations.of(
                          context,
                        )!.global_rss_select_time_button,
                  ),
                ),
              ),
            ],
            if (_selectedFrequency == UpdateFrequency.weekly) ...[
              const SizedBox(height: 20),
              Text(
                AppLocalizations.of(context)!.global_rss_day_of_week,
                style: theme.textTheme.titleMedium?.copyWith(
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 8),
              SegmentedButton<int>(
                segments: List.generate(7, (index) {
                  final l10n = AppLocalizations.of(context)!;
                  final days = [
                    l10n.global_rss_mon,
                    l10n.global_rss_tue,
                    l10n.global_rss_wed,
                    l10n.global_rss_thu,
                    l10n.global_rss_fri,
                    l10n.global_rss_sat,
                    l10n.global_rss_sun,
                  ];
                  return ButtonSegment(
                    value: index + 1,
                    label: Text(days[index]),
                  );
                }),
                selected: {_selectedDayOfWeek ?? 1},
                onSelectionChanged: (Set<int> selected) {
                  setState(() {
                    _selectedDayOfWeek = selected.first;
                  });
                },
              ),
            ],
            const SizedBox(height: 28),
            SizedBox(
              width: double.infinity,
              child: FilledButton.icon(
                onPressed: _isSaving ? null : _applyToAll,
                icon: _isSaving
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Colors.white,
                        ),
                      )
                    : const Icon(Icons.check_circle),
                label: Text(
                  _isSaving
                      ? AppLocalizations.of(context)!.global_rss_applying
                      : AppLocalizations.of(context)!.global_rss_apply_all,
                ),
                style: FilledButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 16),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSubscriptionsList(
    List<ScheduleConfigResponse> schedules,
    ThemeData theme,
  ) {
    return ListView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      itemCount: schedules.length,
      itemBuilder: (context, index) {
        final schedule = schedules[index];
        final l10n = AppLocalizations.of(context)!;
        return Card(
          margin: const EdgeInsets.only(bottom: 8),
          child: ListTile(
            leading: const Icon(Icons.podcasts),
            title: Text(
              schedule.title,
              style: const TextStyle(fontWeight: FontWeight.w500),
            ),
            subtitle: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const SizedBox(height: 4),
                Text(
                  l10n.global_rss_current_label(
                    '${schedule.frequency?.displayName ?? "-"}'
                    '${schedule.updateTime != null ? " ${schedule.updateTime}" : ""}'
                    '${schedule.updateDayOfWeek != null ? " ${_getDayName(schedule.updateDayOfWeek!)}" : ""}',
                  ),
                  style: const TextStyle(fontSize: 12, color: Colors.grey),
                ),
                if (schedule.nextUpdateAt != null)
                  Text(
                    l10n.global_rss_next_label(
                      schedule.nextUpdateDisplay ?? "-",
                    ),
                    style: TextStyle(
                      fontSize: 12,
                      color: theme.colorScheme.primary,
                    ),
                  ),
              ],
            ),
          ),
        );
      },
    );
  }

  String _getDayName(int day) {
    final l10n = AppLocalizations.of(context)!;
    final days = [
      l10n.global_rss_mon,
      l10n.global_rss_tue,
      l10n.global_rss_wed,
      l10n.global_rss_thu,
      l10n.global_rss_fri,
      l10n.global_rss_sat,
      l10n.global_rss_sun,
    ];
    return days[day - 1];
  }

  Future<void> _pickTime() async {
    final picked = await showTimePicker(
      context: context,
      initialTime: _selectedTime ?? const TimeOfDay(hour: 9, minute: 0),
    );
    if (picked != null) {
      setState(() {
        _selectedTime = picked;
      });
    }
  }

  Future<void> _applyToAll() async {
    if (_selectedFrequency == null) return;

    final l10n = AppLocalizations.of(context);
    if (_selectedFrequency == UpdateFrequency.daily && _selectedTime == null) {
      showTopFloatingNotice(
        context,
        message: l10n!.podcast_please_select_time,
        isError: true,
      );
      return;
    }

    if (_selectedFrequency == UpdateFrequency.weekly) {
      if (_selectedTime == null || _selectedDayOfWeek == null) {
        showTopFloatingNotice(
          context,
          message: l10n!.podcast_please_select_time_and_day,
          isError: true,
        );
        return;
      }
    }

    setState(() {
      _isSaving = true;
    });

    final timeStr = _selectedTime != null
        ? '${_selectedTime!.hour.toString().padLeft(2, '0')}:${_selectedTime!.minute.toString().padLeft(2, '0')}'
        : null;

    try {
      final state = ref.read(globalScheduleProvider);
      final allIds = state.schedules.map((s) => s.id).toList();

      final success = await ref
          .read(globalScheduleProvider.notifier)
          .batchUpdateSchedules(
            allIds,
            ScheduleConfigUpdateRequest(
              updateFrequency: _selectedFrequency!.value,
              updateTime: timeStr,
              updateDayOfWeek: _selectedDayOfWeek,
              fetchInterval: _selectedFrequency == UpdateFrequency.hourly
                  ? 3600
                  : null,
            ),
          );

      if (mounted) {
        setState(() {
          _isSaving = false;
        });

        if (success) {
          final l10n = AppLocalizations.of(context);
          showTopFloatingNotice(
            context,
            message: l10n!.podcast_updated_subscriptions(allIds.length),
          );
        } else {
          showTopFloatingNotice(
            context,
            message:
                state.error ??
                AppLocalizations.of(context)!.global_rss_failed_update,
            isError: true,
          );
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isSaving = false;
        });
        showTopFloatingNotice(
          context,
          message: AppLocalizations.of(context)!.error_prefix(e.toString()),
          isError: true,
        );
      }
    }
  }
}
