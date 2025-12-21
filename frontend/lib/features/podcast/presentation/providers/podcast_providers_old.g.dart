// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'podcast_providers_old.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

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
    r'1ff56bed2f427fccd3658fd1720ca121308c71b9';

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

@ProviderFor(PodcastEpisodeNotifier)
const podcastEpisodeProvider = PodcastEpisodeNotifierProvider._();

final class PodcastEpisodeNotifierProvider
    extends
        $NotifierProvider<
          PodcastEpisodeNotifier,
          AsyncValue<PodcastEpisodeListResponse>
        > {
  const PodcastEpisodeNotifierProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'podcastEpisodeProvider',
        isAutoDispose: true,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$podcastEpisodeNotifierHash();

  @$internal
  @override
  PodcastEpisodeNotifier create() => PodcastEpisodeNotifier();

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(AsyncValue<PodcastEpisodeListResponse> value) {
    return $ProviderOverride(
      origin: this,
      providerOverride:
          $SyncValueProvider<AsyncValue<PodcastEpisodeListResponse>>(value),
    );
  }
}

String _$podcastEpisodeNotifierHash() =>
    r'3e5033ee6e4bcebb5f10e06fec0a8e109c744fb8';

abstract class _$PodcastEpisodeNotifier
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
    r'87131e1bdfa8761fe178f535600cad7111c9955d';

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
    r'266ad13aa67f1ebdac0af2ba70de79233da67517';

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

@ProviderFor(PodcastSummaryNotifier)
const podcastSummaryProvider = PodcastSummaryNotifierFamily._();

final class PodcastSummaryNotifierProvider
    extends
        $NotifierProvider<
          PodcastSummaryNotifier,
          AsyncValue<PodcastSummaryResponse?>
        > {
  const PodcastSummaryNotifierProvider._({
    required PodcastSummaryNotifierFamily super.from,
    required int super.argument,
  }) : super(
         retry: null,
         name: r'podcastSummaryProvider',
         isAutoDispose: true,
         dependencies: null,
         $allTransitiveDependencies: null,
       );

  @override
  String debugGetCreateSourceHash() => _$podcastSummaryNotifierHash();

  @override
  String toString() {
    return r'podcastSummaryProvider'
        ''
        '($argument)';
  }

  @$internal
  @override
  PodcastSummaryNotifier create() => PodcastSummaryNotifier();

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(AsyncValue<PodcastSummaryResponse?> value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<AsyncValue<PodcastSummaryResponse?>>(
        value,
      ),
    );
  }

  @override
  bool operator ==(Object other) {
    return other is PodcastSummaryNotifierProvider &&
        other.argument == argument;
  }

  @override
  int get hashCode {
    return argument.hashCode;
  }
}

String _$podcastSummaryNotifierHash() =>
    r'229e4e79cef6a5ef0a7d7b1fdac504419f3582a8';

final class PodcastSummaryNotifierFamily extends $Family
    with
        $ClassFamilyOverride<
          PodcastSummaryNotifier,
          AsyncValue<PodcastSummaryResponse?>,
          AsyncValue<PodcastSummaryResponse?>,
          AsyncValue<PodcastSummaryResponse?>,
          int
        > {
  const PodcastSummaryNotifierFamily._()
    : super(
        retry: null,
        name: r'podcastSummaryProvider',
        dependencies: null,
        $allTransitiveDependencies: null,
        isAutoDispose: true,
      );

  PodcastSummaryNotifierProvider call(int episodeId) =>
      PodcastSummaryNotifierProvider._(argument: episodeId, from: this);

  @override
  String toString() => r'podcastSummaryProvider';
}

abstract class _$PodcastSummaryNotifier
    extends $Notifier<AsyncValue<PodcastSummaryResponse?>> {
  late final _$args = ref.$arg as int;
  int get episodeId => _$args;

  AsyncValue<PodcastSummaryResponse?> build(int episodeId);
  @$mustCallSuper
  @override
  void runBuild() {
    final created = build(_$args);
    final ref =
        this.ref
            as $Ref<
              AsyncValue<PodcastSummaryResponse?>,
              AsyncValue<PodcastSummaryResponse?>
            >;
    final element =
        ref.element
            as $ClassProviderElement<
              AnyNotifier<
                AsyncValue<PodcastSummaryResponse?>,
                AsyncValue<PodcastSummaryResponse?>
              >,
              AsyncValue<PodcastSummaryResponse?>,
              Object?,
              Object?
            >;
    element.handleValue(ref, created);
  }
}
