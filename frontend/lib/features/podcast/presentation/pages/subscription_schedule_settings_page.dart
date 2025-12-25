import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
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
      ref.read(scheduleConfigProvider.notifier).loadConfig(widget.subscriptionId);
    });
  }

  @override
  Widget build(BuildContext context) {
    final configState = ref.watch(scheduleConfigProvider);
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: Text('${widget.subscriptionTitle} - 更新设置'),
        actions: [
          if (configState.config != null)
            IconButton(
              icon: const Icon(Icons.refresh),
              onPressed: () {
                ref.read(scheduleConfigProvider.notifier).loadConfig(widget.subscriptionId);
              },
            ),
        ],
      ),
      body: _buildBody(configState, theme),
    );
  }

  Widget _buildBody(ScheduleConfigState configState, ThemeData theme) {
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
            Text(
              '加载失败',
              style: theme.textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            Text(
              configState.error!,
              style: theme.textTheme.bodyMedium,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: () {
                ref.read(scheduleConfigProvider.notifier).loadConfig(widget.subscriptionId);
              },
              child: const Text('重试'),
            ),
          ],
        ),
      );
    }

    final config = configState.config;
    if (config == null) {
      return const Center(child: Text('没有找到配置信息'));
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
            _buildCurrentScheduleCard(config, theme),
            const SizedBox(height: 24),

            // Update frequency selector
            _buildFrequencySelector(theme),
            const SizedBox(height: 24),

            // Time selector (for DAILY/WEEKLY)
            if (_selectedFrequency == UpdateFrequency.daily ||
                _selectedFrequency == UpdateFrequency.weekly)
              _buildTimeSelector(theme),

            const SizedBox(height: 24),

            // Day of week selector (for WEEKLY)
            if (_selectedFrequency == UpdateFrequency.weekly)
              _buildDaySelector(theme),

            const SizedBox(height: 32),

            // Save button
            SizedBox(
              width: double.infinity,
              child: FilledButton.tonalIcon(
                onPressed: configState.isSaving ? null : _saveConfig,
                icon: configState.isSaving
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.save),
                label: Text(configState.isSaving ? '保存中...' : '保存设置'),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildCurrentScheduleCard(ScheduleConfigResponse config, ThemeData theme) {
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
                  '当前配置',
                  style: theme.textTheme.titleMedium,
                ),
              ],
            ),
            const SizedBox(height: 12),
            _buildScheduleInfoRow('更新频率', config.frequency?.displayName ?? '-'),
            if (config.updateTime != null)
              _buildScheduleInfoRow('更新时间', config.updateTime!),
            if (config.updateDayOfWeek != null)
              _buildScheduleInfoRow('更新星期', '周${_dayOfWeekToString(config.updateDayOfWeek!)}'),
            if (config.nextUpdateAt != null)
              _buildScheduleInfoRow(
                '下次更新',
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

  Widget _buildFrequencySelector(ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('更新频率', style: theme.textTheme.titleMedium),
        const SizedBox(height: 12),
        SegmentedButton<UpdateFrequency>(
          segments: const [
            ButtonSegment(
              value: UpdateFrequency.hourly,
              label: Text('每小时'),
              icon: Icon(Icons.schedule),
            ),
            ButtonSegment(
              value: UpdateFrequency.daily,
              label: Text('每天'),
              icon: Icon(Icons.today),
            ),
            ButtonSegment(
              value: UpdateFrequency.weekly,
              label: Text('每周'),
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

  Widget _buildTimeSelector(ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('更新时间', style: theme.textTheme.titleMedium),
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
              _selectedTime?.format(context) ?? '选择时间',
              style: TextStyle(
                color: _selectedTime != null ? null : Colors.grey,
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildDaySelector(ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('更新星期', style: theme.textTheme.titleMedium),
        const SizedBox(height: 12),
        SegmentedButton<int>(
          segments: List.generate(7, (index) {
            return ButtonSegment(
              value: index + 1,
              label: Text('周${_dayOfWeekToString(index + 1)}'),
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

  Future<void> _saveConfig() async {
    if (_selectedFrequency == null) return;

    // Validate based on frequency
    if (_selectedFrequency == UpdateFrequency.daily && _selectedTime == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('请选择更新时间')),
      );
      return;
    }

    if (_selectedFrequency == UpdateFrequency.weekly) {
      if (_selectedTime == null || _selectedDayOfWeek == null) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('请选择更新时间和星期')),
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
    final success = await ref.read(scheduleConfigProvider.notifier).updateConfig(
      widget.subscriptionId,
      request,
    );

    if (success && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('设置已保存')),
      );
      Navigator.of(context).pop();
    } else if (mounted) {
      final error = ref.read(scheduleConfigProvider).error;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('保存失败: ${error ?? "未知错误"}')),
      );
    }
  }

  String _dayOfWeekToString(int day) {
    const days = ['一', '二', '三', '四', '五', '六', '日'];
    return days[day - 1];
  }
}
