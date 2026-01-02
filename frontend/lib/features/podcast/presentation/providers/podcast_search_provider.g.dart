// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'podcast_search_provider.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning
/// 播客搜索 Notifier

@ProviderFor(PodcastSearchNotifier)
const podcastSearchProvider = PodcastSearchNotifierProvider._();

/// 播客搜索 Notifier
final class PodcastSearchNotifierProvider
    extends $NotifierProvider<PodcastSearchNotifier, PodcastSearchState> {
  /// 播客搜索 Notifier
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
  Override overrideWithValue(PodcastSearchState value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<PodcastSearchState>(value),
    );
  }
}

String _$podcastSearchNotifierHash() =>
    r'428eb0269f753958495ec57977bd1b36bf3be586';

/// 播客搜索 Notifier

abstract class _$PodcastSearchNotifier extends $Notifier<PodcastSearchState> {
  PodcastSearchState build();
  @$mustCallSuper
  @override
  void runBuild() {
    final created = build();
    final ref = this.ref as $Ref<PodcastSearchState, PodcastSearchState>;
    final element =
        ref.element
            as $ClassProviderElement<
              AnyNotifier<PodcastSearchState, PodcastSearchState>,
              PodcastSearchState,
              Object?,
              Object?
            >;
    element.handleValue(ref, created);
  }
}
