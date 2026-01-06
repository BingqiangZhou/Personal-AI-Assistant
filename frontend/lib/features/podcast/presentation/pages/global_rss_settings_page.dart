import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../../core/localization/app_localizations.dart';
import '../../data/models/schedule_config_model.dart';
import '../providers/global_schedule_provider.dart';

class GlobalRSSSettingsPage extends ConsumerStatefulWidget {
  const GlobalRSSSettingsPage({super.key});

  @override
  ConsumerState<GlobalRSSSettingsPage> createState() => _GlobalRSSSettingsPageState();
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
              'Failed to load',
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
              child: const Text('Retry'),
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
            'Affected Subscriptions (${state.schedules.length})',
            style: theme.textTheme.titleLarge?.copyWith(
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 16),
          if (state.schedules.isEmpty)
            const Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(Icons.podcasts, size: 64, color: Colors.grey),
                  SizedBox(height: 16),
                  Text(
                    'No RSS subscriptions',
                    style: TextStyle(fontSize: 18, color: Colors.grey),
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
                        'Update Schedule for All RSS Subscriptions',
                        style: theme.textTheme.titleLarge?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'This will apply to all $subscriptionCount subscriptions',
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
              'Update Frequency',
              style: theme.textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 12),
            SegmentedButton<UpdateFrequency>(
              segments: const [
                ButtonSegment(
                  value: UpdateFrequency.hourly,
                  label: Text('Hourly'),
                  icon: Icon(Icons.access_time_filled),
                ),
                ButtonSegment(
                  value: UpdateFrequency.daily,
                  label: Text('Daily'),
                  icon: Icon(Icons.today),
                ),
                ButtonSegment(
                  value: UpdateFrequency.weekly,
                  label: Text('Weekly'),
                  icon: Icon(Icons.calendar_view_week),
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
                'Update Time',
                style: theme.textTheme.titleMedium?.copyWith(
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 8),
              InkWell(
                onTap: _pickTime,
                child: InputDecorator(
                  decoration: const InputDecoration(
                    border: OutlineInputBorder(),
                    filled: true,
                    suffixIcon: Icon(Icons.access_time),
                    hintText: 'Select time',
                  ),
                  child: Text(
                    _selectedTime?.format(context) ?? 'Select Time',
                  ),
                ),
              ),
            ],
            if (_selectedFrequency == UpdateFrequency.weekly) ...[
              const SizedBox(height: 20),
              Text(
                'Day of Week',
                style: theme.textTheme.titleMedium?.copyWith(
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 8),
              SegmentedButton<int>(
                segments: List.generate(7, (index) {
                  final days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
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
                label: Text(_isSaving ? 'Applying...' : 'Apply to All Subscriptions'),
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

  Widget _buildSubscriptionsList(List<ScheduleConfigResponse> schedules, ThemeData theme) {
    return ListView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      itemCount: schedules.length,
      itemBuilder: (context, index) {
        final schedule = schedules[index];
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
                  'Current: ${schedule.frequency?.displayName ?? "-"}'
                  '${schedule.updateTime != null ? " at ${schedule.updateTime}" : ""}'
                  '${schedule.updateDayOfWeek != null ? " on ${_getDayName(schedule.updateDayOfWeek!)}" : ""}',
                  style: const TextStyle(
                    fontSize: 12,
                    color: Colors.grey,
                  ),
                ),
                if (schedule.nextUpdateAt != null)
                  Text(
                    'Next: ${schedule.nextUpdateDisplay ?? "-"}',
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
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
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
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n!.podcast_please_select_time)),
      );
      return;
    }

    if (_selectedFrequency == UpdateFrequency.weekly) {
      if (_selectedTime == null || _selectedDayOfWeek == null) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(l10n!.podcast_please_select_time_and_day)),
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

      final success = await ref.read(globalScheduleProvider.notifier).batchUpdateSchedules(
            allIds,
            ScheduleConfigUpdateRequest(
              updateFrequency: _selectedFrequency!.value,
              updateTime: timeStr,
              updateDayOfWeek: _selectedDayOfWeek,
              fetchInterval: _selectedFrequency == UpdateFrequency.hourly ? 3600 : null,
            ),
          );

      if (mounted) {
        setState(() {
          _isSaving = false;
        });

        if (success) {
          final l10n = AppLocalizations.of(context);
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(l10n!.podcast_updated_subscriptions(allIds.length)),
              backgroundColor: Colors.green,
            ),
          );
        } else {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(state.error ?? 'Failed to update subscriptions'),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isSaving = false;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }
}
