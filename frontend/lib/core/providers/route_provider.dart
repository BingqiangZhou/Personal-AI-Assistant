import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Provider for tracking the current route location
/// Updated by navigation observers or route changes
final currentRouteProvider = NotifierProvider<CurrentRouteNotifier, String>(CurrentRouteNotifier.new);

class CurrentRouteNotifier extends Notifier<String> {
  @override
  String build() {
    return '/';
  }

  void setRoute(String route) {
    state = route;
  }
}

/// Provider that checks if the current route is a podcast episode detail page
/// where the expanded player overlay should be suppressed
final isOnEpisodeDetailPageProvider = Provider<bool>((ref) {
  final route = ref.watch(currentRouteProvider);
  // Episode detail pages match /podcast/episodes/:id/:id or /podcast/episode/detail/:id
  return route.contains('/podcast/episodes/') || route.contains('/podcast/episode/detail/');
});
