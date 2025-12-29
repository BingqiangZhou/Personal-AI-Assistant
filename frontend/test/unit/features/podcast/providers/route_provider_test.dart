import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:personal_ai_assistant/core/providers/route_provider.dart';

void main() {
  group('RouteProvider Unit Tests', () {
    late ProviderContainer container;

    setUp(() {
      container = ProviderContainer();
    });

    tearDown(() {
      container.dispose();
    });

    group('currentRouteProvider', () {
      test('should have default route value of "/"', () {
        // Act
        final route = container.read(currentRouteProvider);

        // Assert
        expect(route, '/');
      });

      test('should update route when setRoute is called', () {
        // Arrange
        const newRoute = '/podcast/1/player';

        // Act
        container.read(currentRouteProvider.notifier).setRoute(newRoute);

        // Assert
        expect(container.read(currentRouteProvider), newRoute);
      });

      test('should handle multiple route updates', () {
        // Act & Assert - First update
        container.read(currentRouteProvider.notifier).setRoute('/home');
        expect(container.read(currentRouteProvider), '/home');

        // Act & Assert - Second update
        container.read(currentRouteProvider.notifier).setRoute('/podcast/feed');
        expect(container.read(currentRouteProvider), '/podcast/feed');

        // Act & Assert - Third update
        container.read(currentRouteProvider.notifier).setRoute('/settings');
        expect(container.read(currentRouteProvider), '/settings');
      });

      test('should handle routes with query parameters', () {
        // Arrange
        const routeWithQuery = '/podcast/feed?page=2&sort=newest';

        // Act
        container.read(currentRouteProvider.notifier).setRoute(routeWithQuery);

        // Assert
        expect(container.read(currentRouteProvider), routeWithQuery);
      });

      test('should handle deep link routes', () {
        // Arrange
        const deepLinkRoute = '/podcast/123/episode/456/player?position=120';

        // Act
        container.read(currentRouteProvider.notifier).setRoute(deepLinkRoute);

        // Assert
        expect(container.read(currentRouteProvider), deepLinkRoute);
      });
    });

    group('isOnPlayerPageProvider', () {
      test('should return false when on home route', () {
        // Arrange
        container.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        final isOnPlayerPage = container.read(isOnPlayerPageProvider);

        // Assert
        expect(isOnPlayerPage, false);
      });

      test('should return true when on podcast player page route', () {
        // Arrange
        container.read(currentRouteProvider.notifier).setRoute('/podcast/1/player');

        // Act
        final isOnPlayerPage = container.read(isOnPlayerPageProvider);

        // Assert
        expect(isOnPlayerPage, true);
      });

      test('should return true for different subscription IDs', () {
        // Test with subscription ID 1
        container.read(currentRouteProvider.notifier).setRoute('/podcast/1/player');
        expect(container.read(isOnPlayerPageProvider), true);

        // Test with subscription ID 999
        container.read(currentRouteProvider.notifier).setRoute('/podcast/999/player');
        expect(container.read(isOnPlayerPageProvider), true);
      });

      test('should return false when on podcast feed page', () {
        // Arrange
        container.read(currentRouteProvider.notifier).setRoute('/podcast/feed');

        // Act
        final isOnPlayerPage = container.read(isOnPlayerPageProvider);

        // Assert
        expect(isOnPlayerPage, false);
      });

      test('should return false when on podcast subscriptions page', () {
        // Arrange
        container.read(currentRouteProvider.notifier).setRoute('/podcast/subscriptions');

        // Act
        final isOnPlayerPage = container.read(isOnPlayerPageProvider);

        // Assert
        expect(isOnPlayerPage, false);
      });

      test('should return false when on podcast episode detail page', () {
        // Arrange
        container.read(currentRouteProvider.notifier).setRoute('/podcast/episode/123');

        // Act
        final isOnPlayerPage = container.read(isOnPlayerPageProvider);

        // Assert
        expect(isOnPlayerPage, false);
      });

      test('should return true for player page with additional path segments', () {
        // Arrange
        container.read(currentRouteProvider.notifier).setRoute('/podcast/5/player?autoplay=true');

        // Act
        final isOnPlayerPage = container.read(isOnPlayerPageProvider);

        // Assert
        expect(isOnPlayerPage, true);
      });

      test('should reactively update when route changes', () {
        // Start on home page
        container.read(currentRouteProvider.notifier).setRoute('/');
        expect(container.read(isOnPlayerPageProvider), false);

        // Navigate to player page
        container.read(currentRouteProvider.notifier).setRoute('/podcast/42/player');
        expect(container.read(isOnPlayerPageProvider), true);

        // Navigate back to feed
        container.read(currentRouteProvider.notifier).setRoute('/podcast/feed');
        expect(container.read(isOnPlayerPageProvider), false);

        // Navigate to different player page
        container.read(currentRouteProvider.notifier).setRoute('/podcast/100/player');
        expect(container.read(isOnPlayerPageProvider), true);
      });

      test('should handle edge case routes correctly', () {
        // Edge case: route contains player but not in the right pattern
        container.read(currentRouteProvider.notifier).setRoute('/player/podcast');
        expect(container.read(isOnPlayerPageProvider), false);

        // Edge case: route contains podcast but not player
        container.read(currentRouteProvider.notifier).setRoute('/podcast/settings/player');
        expect(container.read(isOnPlayerPageProvider), true);

        // Edge case: empty route
        container.read(currentRouteProvider.notifier).setRoute('');
        expect(container.read(isOnPlayerPageProvider), false);
      });
    });

    group('RouteProvider integration tests', () {
      test('should maintain state consistency between providers', () {
        // Simulate navigation flow
        final notifier = container.read(currentRouteProvider.notifier);

        // 1. Start at home
        notifier.setRoute('/');
        expect(container.read(currentRouteProvider), '/');
        expect(container.read(isOnPlayerPageProvider), false);

        // 2. Navigate to feed
        notifier.setRoute('/podcast/feed');
        expect(container.read(currentRouteProvider), '/podcast/feed');
        expect(container.read(isOnPlayerPageProvider), false);

        // 3. Navigate to player
        notifier.setRoute('/podcast/10/player');
        expect(container.read(currentRouteProvider), '/podcast/10/player');
        expect(container.read(isOnPlayerPageProvider), true);

        // 4. Navigate to episode detail
        notifier.setRoute('/podcast/episode/20');
        expect(container.read(currentRouteProvider), '/podcast/episode/20');
        expect(container.read(isOnPlayerPageProvider), false);

        // 5. Navigate back to player
        notifier.setRoute('/podcast/10/player');
        expect(container.read(currentRouteProvider), '/podcast/10/player');
        expect(container.read(isOnPlayerPageProvider), true);
      });

      test('should handle rapid route changes', () {
        final notifier = container.read(currentRouteProvider.notifier);

        // Simulate rapid navigation
        for (int i = 0; i < 10; i++) {
          notifier.setRoute('/route/$i');
          expect(container.read(currentRouteProvider), '/route/$i');
        }

        // Final state should be the last route set
        expect(container.read(currentRouteProvider), '/route/9');
      });
    });
  });
}
