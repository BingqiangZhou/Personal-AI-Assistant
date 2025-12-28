// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'schedule_provider.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning
/// Schedule configuration notifier

@ProviderFor(ScheduleConfig)
const scheduleConfigProvider = ScheduleConfigProvider._();

/// Schedule configuration notifier
final class ScheduleConfigProvider
    extends $NotifierProvider<ScheduleConfig, ScheduleConfigState> {
  /// Schedule configuration notifier
  const ScheduleConfigProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'scheduleConfigProvider',
        isAutoDispose: true,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$scheduleConfigHash();

  @$internal
  @override
  ScheduleConfig create() => ScheduleConfig();

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(ScheduleConfigState value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<ScheduleConfigState>(value),
    );
  }
}

String _$scheduleConfigHash() => r'10f7736852d1a84f372df29e31cc3eceabeeb8ed';

/// Schedule configuration notifier

abstract class _$ScheduleConfig extends $Notifier<ScheduleConfigState> {
  ScheduleConfigState build();
  @$mustCallSuper
  @override
  void runBuild() {
    final created = build();
    final ref = this.ref as $Ref<ScheduleConfigState, ScheduleConfigState>;
    final element =
        ref.element
            as $ClassProviderElement<
              AnyNotifier<ScheduleConfigState, ScheduleConfigState>,
              ScheduleConfigState,
              Object?,
              Object?
            >;
    element.handleValue(ref, created);
  }
}
