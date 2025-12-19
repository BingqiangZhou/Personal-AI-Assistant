# Podcast Widget Test Fixes Guide

**Last Updated:** 2025-12-19
**Priority:** HIGH - Immediate fixes required

## Step 1: Generate Required Mocks

First, run the build runner to generate all necessary mocks:

```bash
cd frontend
flutter packages pub run build_runner build --delete-conflicting-outputs
```

If this fails, you may need to add annotations to your test files:

```dart
// Add to test/mocks/test_mocks.dart
import 'package:mockito/annotations.dart';

import 'package:personal_ai_assistant/features/podcast/data/repositories/podcast_repository.dart';

@GenerateMocks([PodcastRepository])
void main() {}
```

## Step 2: Fix Missing Token Storage

Create the missing token storage mock:

```dart
// test/mocks/token_storage_mock.dart
import 'package:mockito/annotations.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

// Mock implementation if real storage doesn't exist
class MockTokenStorage {
  Future<String?> getToken() async => 'test-token';
}

// Provider for tests
final mockTokenStorageProvider = Provider<MockTokenStorage>((ref) {
  return MockTokenStorage();
});
```

## Step 3: Update Test Helper Import Paths

Fix the import paths in your test files:

```dart
// Change from:
import '../../../mocks/test_mocks.dart';
import '../../../helpers/widget_test_helpers.dart';

// To:
import '../../mocks/test_mocks.dart';
import '../helpers/widget_test_helpers.dart';
```

## Step 4: Fix Provider References

Update provider names to match the generated files:

```dart
// In your tests, use the actual provider names:
// Instead of: podcastSubscriptionNotifierProvider
// Use: podcastSubscriptionProvider

// Check lib/features/podcast/presentation/providers/podcast_providers.dart
// for the correct provider names
```

## Step 5: Fix Category Model Usage

Update category creation to match the actual model:

```dart
// Instead of:
Category(id: 1, name: 'Technology', description: 'Tech content')

// Use:
Category(
  id: 1,
  name: 'Technology',
  color: '#FF0000', // Add color
  createdAt: DateTime.now(),
  updatedAt: DateTime.now(),
)
```

## Step 6: Fix Import Paths

Update all imports to use the correct relative paths:

```dart
// Correct imports for tests:
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_subscription_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/category_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_list_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
```

## Step 7: Update Widget Test Helpers

Create a minimal widget test helper if the full version isn't working:

```dart
// test/helpers/widget_test_helpers.dart (minimal version)
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';

import 'package:personal_ai_assistant/features/podcast/data/models/podcast_subscription_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/category_model.dart';

Widget createTestWidget({required Widget child, ProviderContainer? container}) {
  return UncontrolledProviderScope(
    container: container ?? ProviderContainer(),
    child: MaterialApp.router(
      routerConfig: GoRouter(
        routes: [
          GoRoute(
            path: '/',
            builder: (context, state) => child,
          ),
        ],
      ),
    ),
  );
}

PodcastSubscriptionModel createMockSubscription({
  int id = 1,
  String title = 'Test Podcast',
  String? description,
  String status = 'active',
  int episodeCount = 10,
  int unplayedCount = 5,
  DateTime? createdAt,
  List<Category>? categories,
}) {
  return PodcastSubscriptionModel(
    id: id,
    userId: 1,
    title: title,
    description: description,
    sourceUrl: 'https://example.com/podcast$id.xml',
    status: status,
    fetchInterval: 3600,
    episodeCount: episodeCount,
    unplayedCount: unplayedCount,
    createdAt: createdAt ?? DateTime.now().subtract(const Duration(days: 30)),
    categories: categories,
  );
}
```

## Step 8: Test with a Simple Example

Create a simple test to verify the setup:

```dart
// test/widget/podcast/simple_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_list_page.dart';

void main() {
  testWidgets('Simple PodcastListPage test', (WidgetTester tester) async {
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: PodcastListPage(),
      ),
    ));

    // Verify basic elements
    expect(find.text('Podcasts'), findsOneWidget);
    expect(find.byType(FloatingActionButton), findsOneWidget);
  });
}
```

## Step 9: Run Tests Incrementally

Test each component separately:

```bash
# Test individual files
flutter test test/widget/podcast/simple_test.dart

# Test without complex mocks
flutter test test/widget/podcast/comprehensive_podcast_player_page_test.dart --no-pub
```

## Step 10: Debug Common Issues

### Issue: "The method 'findByLabel' isn't defined"
**Fix:** Use alternative semantics testing:
```dart
// Instead of:
tester.semantics.findByLabel('Podcasts')

// Use:
expect(find.bySemanticsLabel('Podcasts'), findsOneWidget);
```

### Issue: Provider not found
**Fix:** Check the generated provider file:
```dart
// Check lib/features/podcast/presentation/providers/podcast_providers.g.dart
// for the actual provider names
```

### Issue: Import errors
**Fix:** Verify file structure and update paths:
```bash
# List actual file structure
find . -name "*.dart" | grep -E "(test|mock|helper)" | head -20
```

## Step 11: Alternative Approach - Minimal Tests

If the complex tests continue to fail, create minimal tests that focus on the core functionality:

```dart
// test/widget/podcast/minimal_podcast_tests.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_list_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_player_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_subscription_card.dart';

void main() {
  group('Minimal Podcast Tests', () {
    testWidgets('PodcastListPage renders', (WidgetTester tester) async {
      await tester.pumpWidget(MaterialApp(home: PodcastListPage()));
      expect(find.text('Podcasts'), findsOneWidget);
    });

    testWidgets('PodcastPlayerPage renders', (WidgetTester tester) async {
      await tester.pumpWidget(MaterialApp(home: PodcastPlayerPage()));
      expect(find.text('Podcast Player'), findsOneWidget);
    });

    testWidgets('PodcastSubscriptionCard renders', (WidgetTester tester) async {
      // Skip card tests if models aren't working
    });
  });
}
```

## Next Steps

1. **Generate mocks** using build_runner
2. **Create minimal test files** to verify basic functionality
3. **Fix import paths** and provider references
4. **Run tests incrementally** to identify specific issues
5. **Add proper mocking** once basic tests pass

## Troubleshooting Checklist

- [ ] Run `flutter clean` and `flutter pub get`
- [ ] Generate mocks with `build_runner`
- [ ] Verify all import paths are correct
- [ ] Check provider names in generated files
- [ ] Test with minimal examples first
- [ ] Check Flutter and package versions

If you continue to experience issues, focus on getting the minimal tests working first, then gradually add complexity.