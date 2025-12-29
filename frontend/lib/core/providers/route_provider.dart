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

/// Provider that checks if the current route is the podcast player page
/// Returns true if the user is on the player page, false otherwise
final isOnPlayerPageProvider = Provider<bool>((ref) {
  final route = ref.watch(currentRouteProvider);
  // Check if the route path matches the player page pattern
  return route.contains('/podcast/') && route.contains('/player');
});
