// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'global_schedule_provider.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(GlobalSchedule)
final globalScheduleProvider = GlobalScheduleProvider._();

final class GlobalScheduleProvider
    extends $NotifierProvider<GlobalSchedule, GlobalScheduleState> {
  GlobalScheduleProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'globalScheduleProvider',
        isAutoDispose: true,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$globalScheduleHash();

  @$internal
  @override
  GlobalSchedule create() => GlobalSchedule();

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(GlobalScheduleState value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<GlobalScheduleState>(value),
    );
  }
}

String _$globalScheduleHash() => r'4aa04b33d7f21d950b44766ec22a8b1c15f102d0';

abstract class _$GlobalSchedule extends $Notifier<GlobalScheduleState> {
  GlobalScheduleState build();
  @$mustCallSuper
  @override
  void runBuild() {
    final ref = this.ref as $Ref<GlobalScheduleState, GlobalScheduleState>;
    final element =
        ref.element
            as $ClassProviderElement<
              AnyNotifier<GlobalScheduleState, GlobalScheduleState>,
              GlobalScheduleState,
              Object?,
              Object?
            >;
    element.handleCreate(ref, build);
  }
}
