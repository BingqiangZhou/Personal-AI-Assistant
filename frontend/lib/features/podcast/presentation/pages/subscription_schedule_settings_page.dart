import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../../core/localization/app_localizations.dart';
import '../../../../core/widgets/top_floating_notice.dart';
import '../../data/models/schedule_config_model.dart';
import '../providers/schedule_provider.dart';

class SubscriptionScheduleSettingsPage extends ConsumerStatefulWidget {
  final int subscriptionId;
  final String subscriptionTitle;

  const SubscriptionScheduleSettingsPage({
    super.key,
    required this.subscriptionId,
    required this.subscriptionTitle,
  });

  @override
  ConsumerState<SubscriptionScheduleSettingsPage> createState() =>
      _SubscriptionScheduleSettingsPageState();
}

class _SubscriptionScheduleSettingsPageState
    extends ConsumerState<SubscriptionScheduleSettingsPage> {
  final _formKey = GlobalKey<FormState>();

  UpdateFrequency? _selectedFrequency;
  TimeOfDay? _selectedTime;
  int? _selectedDayOfWeek;

  @override
  void initState() {
    super.initState();
    // Load existing config
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref
          .read(scheduleConfigProvider.notifier)
          .loadConfig(widget.subscriptionId);
    });
  }

  @override
  Widget build(BuildContext context) {
    final configState = ref.watch(scheduleConfigProvider);
    final theme = Theme.of(context);
    final l10n = AppLocalizations.of(context)!;

    return Scaffold(
      appBar: AppBar(
        title: Text('${widget.subscriptionTitle} - ${l10n.schedule_settings}'),
        actions: [
          if (configState.config != null)
            IconButton(
              icon: const Icon(Icons.refresh),
              onPressed: () {
                ref
                    .read(scheduleConfigProvider.notifier)
                    .loadConfig(widget.subscriptionId);
              },
            ),
        ],
      ),
      body: _buildBody(configState, theme, l10n),
    );
  }

  Widget _buildBody(
    ScheduleConfigState configState,
    ThemeData theme,
    AppLocalizations l10n,
  ) {
    if (configState.isLoading) {
      return const Center(child: CircularProgressIndicator());
    }

    if (configState.error != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 48, color: Colors.red),
            const SizedBox(height: 16),
            Text(l10n.schedule_load_failed, style: theme.textTheme.titleLarge),
            const SizedBox(height: 8),
            Text(
              configState.error!,
              style: theme.textTheme.bodyMedium,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: () {
                ref
                    .read(scheduleConfigProvider.notifier)
                    .loadConfig(widget.subscriptionId);
              },
              child: Text(l10n.retry),
            ),
          ],
        ),
      );
    }

    final config = configState.config;
    if (config == null) {
      return Center(child: Text(l10n.schedule_no_config));
    }

    // Initialize form fields from config
    if (_selectedFrequency == null && config.frequency != null) {
      _selectedFrequency = config.frequency;
      if (config.updateTime != null) {
        final parts = config.updateTime!.split(':');
        _selectedTime = TimeOfDay(
          hour: int.parse(parts[0]),
          minute: int.parse(parts[1]),
        );
      }
      _selectedDayOfWeek = config.updateDayOfWeek;
    }

    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Form(
        key: _formKey,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Current schedule info card
            _buildCurrentScheduleCard(config, theme, l10n),
            const SizedBox(height: 24),

            // Update frequency selector
            _buildFrequencySelector(theme, l10n),
            const SizedBox(height: 24),

            // Time selector (for DAILY/WEEKLY)
            if (_selectedFrequency == UpdateFrequency.daily ||
                _selectedFrequency == UpdateFrequency.weekly)
              _buildTimeSelector(theme, l10n),

            const SizedBox(height: 24),

            // Day of week selector (for WEEKLY)
            if (_selectedFrequency == UpdateFrequency.weekly)
              _buildDaySelector(theme, l10n),

            const SizedBox(height: 32),

            // Save button
            SizedBox(
              width: double.infinity,
              child: FilledButton.tonalIcon(
                onPressed: configState.isSaving
                    ? null
                    : () => _saveConfig(l10n),
                icon: configState.isSaving
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.save),
                label: Text(
                  configState.isSaving
                      ? l10n.schedule_saving
                      : l10n.schedule_save_settings,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildCurrentScheduleCard(
    ScheduleConfigResponse config,
    ThemeData theme,
    AppLocalizations l10n,
  ) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.schedule, color: theme.colorScheme.primary),
                const SizedBox(width: 8),
                Text(
                  l10n.schedule_current_config,
                  style: theme.textTheme.titleMedium,
                ),
              ],
            ),
            const SizedBox(height: 12),
            _buildScheduleInfoRow(
              l10n.schedule_update_frequency,
              config.frequency?.displayName ?? '-',
            ),
            if (config.updateTime != null)
              _buildScheduleInfoRow(
                l10n.schedule_update_time,
                config.updateTime!,
              ),
            if (config.updateDayOfWeek != null)
              _buildScheduleInfoRow(
                l10n.schedule_update_day,
                '${l10n.schedule_week_short} ${_dayOfWeekToString(config.updateDayOfWeek!, l10n)}',
              ),
            if (config.nextUpdateAt != null)
              _buildScheduleInfoRow(
                l10n.schedule_next_update,
                config.nextUpdateDisplay ?? '-',
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildScheduleInfoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: const TextStyle(color: Colors.grey)),
          Text(value, style: const TextStyle(fontWeight: FontWeight.bold)),
        ],
      ),
    );
  }

  Widget _buildFrequencySelector(ThemeData theme, AppLocalizations l10n) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          l10n.schedule_update_frequency,
          style: theme.textTheme.titleMedium,
        ),
        const SizedBox(height: 12),
        SegmentedButton<UpdateFrequency>(
          segments: [
            ButtonSegment(
              value: UpdateFrequency.hourly,
              label: Text(l10n.schedule_hourly),
              icon: Icon(Icons.schedule),
            ),
            ButtonSegment(
              value: UpdateFrequency.daily,
              label: Text(l10n.schedule_daily),
              icon: Icon(Icons.today),
            ),
            ButtonSegment(
              value: UpdateFrequency.weekly,
              label: Text(l10n.schedule_weekly),
              icon: Icon(Icons.calendar_view_week),
            ),
          ],
          selected: {_selectedFrequency ?? UpdateFrequency.hourly},
          onSelectionChanged: (Set<UpdateFrequency> selected) {
            setState(() {
              _selectedFrequency = selected.first;
              // Reset time and day when frequency changes
              if (_selectedFrequency == UpdateFrequency.hourly) {
                _selectedTime = null;
                _selectedDayOfWeek = null;
              }
            });
          },
        ),
      ],
    );
  }

  Widget _buildTimeSelector(ThemeData theme, AppLocalizations l10n) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(l10n.schedule_update_time, style: theme.textTheme.titleMedium),
        const SizedBox(height: 12),
        InkWell(
          onTap: _pickTime,
          child: InputDecorator(
            decoration: InputDecoration(
              border: OutlineInputBorder(),
              filled: true,
              suffixIcon: const Icon(Icons.access_time),
            ),
            child: Text(
              _selectedTime?.format(context) ?? l10n.schedule_select_time,
              style: TextStyle(
                color: _selectedTime != null ? null : Colors.grey,
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildDaySelector(ThemeData theme, AppLocalizations l10n) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(l10n.schedule_update_day, style: theme.textTheme.titleMedium),
        const SizedBox(height: 12),
        SegmentedButton<int>(
          segments: List.generate(7, (index) {
            return ButtonSegment(
              value: index + 1,
              label: Text(
                '${l10n.schedule_week_short} ${_dayOfWeekToString(index + 1, l10n)}',
              ),
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
    );
  }

  Future<void> _pickTime() async {
    final picked = await showTimePicker(
      context: context,
      initialTime: _selectedTime ?? const TimeOfDay(hour: 9, minute: 0),
      builder: (context, child) {
        return MediaQuery(
          data: MediaQuery.of(context).copyWith(alwaysUse24HourFormat: true),
          child: child!,
        );
      },
    );
    if (picked != null) {
      setState(() {
        _selectedTime = picked;
      });
    }
  }

  Future<void> _saveConfig(AppLocalizations l10n) async {
    if (_selectedFrequency == null) return;

    // Validate based on frequency
    if (_selectedFrequency == UpdateFrequency.daily && _selectedTime == null) {
      showTopFloatingNotice(
        context,
        message: l10n.schedule_select_update_time,
        isError: true,
      );
      return;
    }

    if (_selectedFrequency == UpdateFrequency.weekly) {
      if (_selectedTime == null || _selectedDayOfWeek == null) {
        showTopFloatingNotice(
          context,
          message: l10n.schedule_select_time_and_day,
          isError: true,
        );
        return;
      }
    }

    // Create request
    final request = ScheduleConfigUpdateRequest(
      updateFrequency: _selectedFrequency!.value,
      updateTime: _selectedTime != null
          ? '${_selectedTime!.hour.toString().padLeft(2, '0')}:${_selectedTime!.minute.toString().padLeft(2, '0')}'
          : null,
      updateDayOfWeek: _selectedDayOfWeek,
      fetchInterval: _selectedFrequency == UpdateFrequency.hourly ? 3600 : null,
    );

    // Save
    final success = await ref
        .read(scheduleConfigProvider.notifier)
        .updateConfig(widget.subscriptionId, request);

    if (success && mounted) {
      showTopFloatingNotice(context, message: l10n.schedule_settings_saved);
      Navigator.of(context).pop();
    } else if (mounted) {
      final error = ref.read(scheduleConfigProvider).error;
      showTopFloatingNotice(
        context,
        message:
            '${l10n.schedule_save_failed}: ${error ?? l10n.schedule_unknown_error}',
        isError: true,
      );
    }
  }

  String _dayOfWeekToString(int day, AppLocalizations l10n) {
    // Use localized day names
    final days = [
      l10n.schedule_day_mon,
      l10n.schedule_day_tue,
      l10n.schedule_day_wed,
      l10n.schedule_day_thu,
      l10n.schedule_day_fri,
      l10n.schedule_day_sat,
      l10n.schedule_day_sun,
    ];
    return days[day - 1];
  }
}
