// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'podcast_providers.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(AudioPlayerNotifier)
const audioPlayerProvider = AudioPlayerNotifierProvider._();

final class AudioPlayerNotifierProvider
    extends $NotifierProvider<AudioPlayerNotifier, AudioPlayerState> {
  const AudioPlayerNotifierProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'audioPlayerProvider',
        isAutoDispose: true,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$audioPlayerNotifierHash();

  @$internal
  @override
  AudioPlayerNotifier create() => AudioPlayerNotifier();

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(AudioPlayerState value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<AudioPlayerState>(value),
    );
  }
}

String _$audioPlayerNotifierHash() =>
    r'1381b316fe1936198c8c04522f2feabbd5247fc0';

abstract class _$AudioPlayerNotifier extends $Notifier<AudioPlayerState> {
  AudioPlayerState build();
  @$mustCallSuper
  @override
  void runBuild() {
    final created = build();
    final ref = this.ref as $Ref<AudioPlayerState, AudioPlayerState>;
    final element =
        ref.element
            as $ClassProviderElement<
              AnyNotifier<AudioPlayerState, AudioPlayerState>,
              AudioPlayerState,
              Object?,
              Object?
            >;
    element.handleValue(ref, created);
  }
}

@ProviderFor(PodcastSubscriptionNotifier)
const podcastSubscriptionProvider = PodcastSubscriptionNotifierProvider._();

final class PodcastSubscriptionNotifierProvider
    extends
        $NotifierProvider<
          PodcastSubscriptionNotifier,
          AsyncValue<PodcastSubscriptionListResponse>
        > {
  const PodcastSubscriptionNotifierProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'podcastSubscriptionProvider',
        isAutoDispose: true,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$podcastSubscriptionNotifierHash();

  @$internal
  @override
  PodcastSubscriptionNotifier create() => PodcastSubscriptionNotifier();

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(
    AsyncValue<PodcastSubscriptionListResponse> value,
  ) {
    return $ProviderOverride(
      origin: this,
      providerOverride:
          $SyncValueProvider<AsyncValue<PodcastSubscriptionListResponse>>(
            value,
          ),
    );
  }
}

String _$podcastSubscriptionNotifierHash() =>
    r'195777825dadd95b412d5619ff0b5563700dcf94';

abstract class _$PodcastSubscriptionNotifier
    extends $Notifier<AsyncValue<PodcastSubscriptionListResponse>> {
  AsyncValue<PodcastSubscriptionListResponse> build();
  @$mustCallSuper
  @override
  void runBuild() {
    final created = build();
    final ref =
        this.ref
            as $Ref<
              AsyncValue<PodcastSubscriptionListResponse>,
              AsyncValue<PodcastSubscriptionListResponse>
            >;
    final element =
        ref.element
            as $ClassProviderElement<
              AnyNotifier<
                AsyncValue<PodcastSubscriptionListResponse>,
                AsyncValue<PodcastSubscriptionListResponse>
              >,
              AsyncValue<PodcastSubscriptionListResponse>,
              Object?,
              Object?
            >;
    element.handleValue(ref, created);
  }
}

@ProviderFor(PodcastFeedNotifier)
const podcastFeedProvider = PodcastFeedNotifierProvider._();

final class PodcastFeedNotifierProvider
    extends $NotifierProvider<PodcastFeedNotifier, PodcastFeedState> {
  const PodcastFeedNotifierProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'podcastFeedProvider',
        isAutoDispose: true,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$podcastFeedNotifierHash();

  @$internal
  @override
  PodcastFeedNotifier create() => PodcastFeedNotifier();

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(PodcastFeedState value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<PodcastFeedState>(value),
    );
  }
}

String _$podcastFeedNotifierHash() =>
    r'c3e947b3462c4b8663203b3acbaac937b3634fd8';

abstract class _$PodcastFeedNotifier extends $Notifier<PodcastFeedState> {
  PodcastFeedState build();
  @$mustCallSuper
  @override
  void runBuild() {
    final created = build();
    final ref = this.ref as $Ref<PodcastFeedState, PodcastFeedState>;
    final element =
        ref.element
            as $ClassProviderElement<
              AnyNotifier<PodcastFeedState, PodcastFeedState>,
              PodcastFeedState,
              Object?,
              Object?
            >;
    element.handleValue(ref, created);
  }
}

@ProviderFor(PodcastSearchNotifier)
const podcastSearchProvider = PodcastSearchNotifierProvider._();

final class PodcastSearchNotifierProvider
    extends
        $NotifierProvider<
          PodcastSearchNotifier,
          AsyncValue<PodcastEpisodeListResponse>
        > {
  const PodcastSearchNotifierProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'podcastSearchProvider',
        isAutoDispose: true,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$podcastSearchNotifierHash();

  @$internal
  @override
  PodcastSearchNotifier create() => PodcastSearchNotifier();

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(AsyncValue<PodcastEpisodeListResponse> value) {
    return $ProviderOverride(
      origin: this,
      providerOverride:
          $SyncValueProvider<AsyncValue<PodcastEpisodeListResponse>>(value),
    );
  }
}

String _$podcastSearchNotifierHash() =>
    r'9f89c0dcb9253156a5bfe459597a513717ba3ad2';

abstract class _$PodcastSearchNotifier
    extends $Notifier<AsyncValue<PodcastEpisodeListResponse>> {
  AsyncValue<PodcastEpisodeListResponse> build();
  @$mustCallSuper
  @override
  void runBuild() {
    final created = build();
    final ref =
        this.ref
            as $Ref<
              AsyncValue<PodcastEpisodeListResponse>,
              AsyncValue<PodcastEpisodeListResponse>
            >;
    final element =
        ref.element
            as $ClassProviderElement<
              AnyNotifier<
                AsyncValue<PodcastEpisodeListResponse>,
                AsyncValue<PodcastEpisodeListResponse>
              >,
              AsyncValue<PodcastEpisodeListResponse>,
              Object?,
              Object?
            >;
    element.handleValue(ref, created);
  }
}

@ProviderFor(podcastStatsProvider)
const podcastStatsProviderProvider = PodcastStatsProviderProvider._();

final class PodcastStatsProviderProvider
    extends
        $FunctionalProvider<
          AsyncValue<PodcastStatsResponse?>,
          PodcastStatsResponse?,
          FutureOr<PodcastStatsResponse?>
        >
    with
        $FutureModifier<PodcastStatsResponse?>,
        $FutureProvider<PodcastStatsResponse?> {
  const PodcastStatsProviderProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'podcastStatsProviderProvider',
        isAutoDispose: true,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$podcastStatsProviderHash();

  @$internal
  @override
  $FutureProviderElement<PodcastStatsResponse?> $createElement(
    $ProviderPointer pointer,
  ) => $FutureProviderElement(pointer);

  @override
  FutureOr<PodcastStatsResponse?> create(Ref ref) {
    return podcastStatsProvider(ref);
  }
}

String _$podcastStatsProviderHash() =>
    r'3e6feaa068e0d317fc5891e78b62e4694650f172';

@ProviderFor(episodeDetailProvider)
const episodeDetailProviderProvider = EpisodeDetailProviderFamily._();

final class EpisodeDetailProviderProvider
    extends
        $FunctionalProvider<
          AsyncValue<PodcastEpisodeDetailResponse?>,
          PodcastEpisodeDetailResponse?,
          FutureOr<PodcastEpisodeDetailResponse?>
        >
    with
        $FutureModifier<PodcastEpisodeDetailResponse?>,
        $FutureProvider<PodcastEpisodeDetailResponse?> {
  const EpisodeDetailProviderProvider._({
    required EpisodeDetailProviderFamily super.from,
    required int super.argument,
  }) : super(
         retry: null,
         name: r'episodeDetailProviderProvider',
         isAutoDispose: true,
         dependencies: null,
         $allTransitiveDependencies: null,
       );

  @override
  String debugGetCreateSourceHash() => _$episodeDetailProviderHash();

  @override
  String toString() {
    return r'episodeDetailProviderProvider'
        ''
        '($argument)';
  }

  @$internal
  @override
  $FutureProviderElement<PodcastEpisodeDetailResponse?> $createElement(
    $ProviderPointer pointer,
  ) => $FutureProviderElement(pointer);

  @override
  FutureOr<PodcastEpisodeDetailResponse?> create(Ref ref) {
    final argument = this.argument as int;
    return episodeDetailProvider(ref, argument);
  }

  @override
  bool operator ==(Object other) {
    return other is EpisodeDetailProviderProvider && other.argument == argument;
  }

  @override
  int get hashCode {
    return argument.hashCode;
  }
}

String _$episodeDetailProviderHash() =>
    r'32765802ad1317473778080316231a06d79a61c8';

final class EpisodeDetailProviderFamily extends $Family
    with
        $FunctionalFamilyOverride<
          FutureOr<PodcastEpisodeDetailResponse?>,
          int
        > {
  const EpisodeDetailProviderFamily._()
    : super(
        retry: null,
        name: r'episodeDetailProviderProvider',
        dependencies: null,
        $allTransitiveDependencies: null,
        isAutoDispose: true,
      );

  EpisodeDetailProviderProvider call(int episodeId) =>
      EpisodeDetailProviderProvider._(argument: episodeId, from: this);

  @override
  String toString() => r'episodeDetailProviderProvider';
}

@ProviderFor(PodcastEpisodesNotifier)
const podcastEpisodesProvider = PodcastEpisodesNotifierFamily._();

final class PodcastEpisodesNotifierProvider
    extends $NotifierProvider<PodcastEpisodesNotifier, PodcastEpisodesState> {
  const PodcastEpisodesNotifierProvider._({
    required PodcastEpisodesNotifierFamily super.from,
    required int super.argument,
  }) : super(
         retry: null,
         name: r'podcastEpisodesProvider',
         isAutoDispose: true,
         dependencies: null,
         $allTransitiveDependencies: null,
       );

  @override
  String debugGetCreateSourceHash() => _$podcastEpisodesNotifierHash();

  @override
  String toString() {
    return r'podcastEpisodesProvider'
        ''
        '($argument)';
  }

  @$internal
  @override
  PodcastEpisodesNotifier create() => PodcastEpisodesNotifier();

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(PodcastEpisodesState value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<PodcastEpisodesState>(value),
    );
  }

  @override
  bool operator ==(Object other) {
    return other is PodcastEpisodesNotifierProvider &&
        other.argument == argument;
  }

  @override
  int get hashCode {
    return argument.hashCode;
  }
}

String _$podcastEpisodesNotifierHash() =>
    r'ad95437089fac13c1aa81af7ba76d1a8575fe018';

final class PodcastEpisodesNotifierFamily extends $Family
    with
        $ClassFamilyOverride<
          PodcastEpisodesNotifier,
          PodcastEpisodesState,
          PodcastEpisodesState,
          PodcastEpisodesState,
          int
        > {
  const PodcastEpisodesNotifierFamily._()
    : super(
        retry: null,
        name: r'podcastEpisodesProvider',
        dependencies: null,
        $allTransitiveDependencies: null,
        isAutoDispose: true,
      );

  PodcastEpisodesNotifierProvider call(int subscriptionId) =>
      PodcastEpisodesNotifierProvider._(argument: subscriptionId, from: this);

  @override
  String toString() => r'podcastEpisodesProvider';
}

abstract class _$PodcastEpisodesNotifier
    extends $Notifier<PodcastEpisodesState> {
  late final _$args = ref.$arg as int;
  int get subscriptionId => _$args;

  PodcastEpisodesState build(int subscriptionId);
  @$mustCallSuper
  @override
  void runBuild() {
    final created = build(_$args);
    final ref = this.ref as $Ref<PodcastEpisodesState, PodcastEpisodesState>;
    final element =
        ref.element
            as $ClassProviderElement<
              AnyNotifier<PodcastEpisodesState, PodcastEpisodesState>,
              PodcastEpisodesState,
              Object?,
              Object?
            >;
    element.handleValue(ref, created);
  }
}
