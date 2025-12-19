# Flutter Test Architecture Guide

## Overview

This document outlines the comprehensive test architecture for the Flutter podcast feature, focusing on maintainable, scalable testing practices.

## Architecture Principles

### 1. **Test Structure**
```
test/
├── mocks/                    # Mock infrastructure
│   ├── test_mocks.dart      # Central mock generation
│   ├── mock_helpers.dart    # Test utilities
│   └── fixture_factories.dart # Test data factories
├── unit/                    # Unit tests
└── widget/                  # Widget tests
    └── features/
        └── podcast/
            ├── pages/       # Page-level widget tests
            └── components/  # Component widget tests
```

### 2. **Mock Strategy**

#### Centralized Mock Management
- All mocks generated from `test/mocks/test_mocks.dart`
- Use `@GenerateMocks()` annotation for automatic generation
- Mocks are version-controlled in `test/mocks/test_mocks.g.dart`

#### Test Helpers
- `TestProviderContainer` - Creates ProviderContainer with overrides
- `ProviderTestWrapper` - Widget wrapper for provider testing
- `MockSetupHelpers` - Common mock configurations

### 3. **Test Data Management**

#### Factory Pattern for Test Data
```dart
// Use factories for consistent test data
final subscription = PodcastSubscriptionFactory.create(
  id: 1,
  title: 'Test Podcast',
);

final episodes = PodcastEpisodeFactory.createList(3);
```

#### Benefits:
- Consistent test data across all tests
- Easy to create variations (with error states, different statuses)
- Single source of truth for test data structure

## Testing Best Practices

### 1. **Widget Testing Rules**

#### MANDATORY: Widget Tests for Pages
- All page functionality MUST be tested with `testWidgets`
- Unit tests only for pure logic functions
- Integration tests for complete user workflows

#### Required Test Scenarios for Every Page:
- Renders all required UI components
- Displays loading state initially
- Shows data when loaded successfully
- Handles error states appropriately
- Navigation works correctly
- Empty state displays correctly
- Pull to refresh (if applicable)
- Search/filter functionality (if applicable)

### 2. **Provider Testing**

#### Provider Overrides in Tests
```dart
late ProviderContainer container;
late MockPodcastRepository mockRepository;

setUp(() {
  mockRepository = MockPodcastRepository();
  container = TestProviderContainer.createWithOverrides(
    repository: mockRepository,
  );
});
```

#### Best Practices:
- Always dispose containers in `tearDown()`
- Use `TestProviderContainer` for consistent setup
- Mock all external dependencies

### 3. **Navigation Testing**

#### Navigation Arguments Pattern
```dart
// Factory constructors for different navigation patterns
factory PodcastEpisodesPage.fromArgs(PodcastEpisodesPageArgs args)
factory PodcastEpisodesPage.withSubscription(PodcastSubscription subscription)
```

#### Benefits:
- Type-safe navigation
- Consistent parameter passing
- Easier testing with different navigation scenarios

### 4. **Error Handling Tests**

#### Test All Error Scenarios:
- Network connectivity issues
- API errors (4xx, 5xx)
- JSON parsing errors
- Data validation errors
- Permission errors

### 5. **Accessibility Testing**

#### Semantic Labels
```dart
expect(
  tester.semantics.findByLabel('Episode Title'),
  findsOneWidget,
);
```

## Common Test Patterns

### 1. **Page Load Test**
```dart
testWidgets('renders page with loading state', (WidgetTester tester) async {
  // Arrange
  MockSetupHelpers.setupRepositoryLoading(mockRepository, subscriptionId);

  // Act
  await tester.pumpWidgetWithProviders(
    PodcastEpisodesPage.withSubscription(subscription),
    container: container,
  );
  await tester.pump();

  // Assert
  expect(find.byType(CircularProgressIndicator), findsOneWidget);
  expect(find.text('Podcast Title'), findsOneWidget);
});
```

### 2. **Success State Test**
```dart
testWidgets('displays data when loaded successfully', (WidgetTester tester) async {
  // Arrange
  final episodes = PodcastEpisodeFactory.createList(3);
  MockSetupHelpers.setupRepositorySuccess(mockRepository, subscriptionId, episodes);

  // Act & Assert
  await tester.pumpWidgetWithProviders(...);
  await tester.pumpAndSettle();

  expect(find.text('Episode 1'), findsOneWidget);
  expect(find.text('Episode 2'), findsOneWidget);
  expect(find.text('Episode 3'), findsOneWidget);
});
```

### 3. **Error State Test**
```dart
testWidgets('displays error when loading fails', (WidgetTester tester) async {
  // Arrange
  MockSetupHelpers.setupRepositoryError(
    mockRepository,
    subscriptionId,
    errorMessage: 'Network error',
  );

  // Act & Assert
  await tester.pumpWidgetWithProviders(...);
  await tester.pumpAndSettle();

  expect(find.text('Failed to load'), findsOneWidget);
  expect(find.text('Network error'), findsOneWidget);
  expect(find.text('Retry'), findsOneWidget);
});
```

## Running Tests

### Generate Mocks
```bash
# Generate all mocks
flutter packages pub run build_runner build --delete-conflicting-outputs

# Or run the helper script
dart test/generate_mocks.dart
```

### Run Widget Tests
```bash
# Run all widget tests
flutter test test/widget/

# Run specific feature tests
flutter test test/widget/features/podcast/

# Run with coverage
flutter test --coverage
```

### Run Specific Test File
```bash
flutter test test/widget/features/podcast/podcast_episodes_page_test.dart
```

## Maintenance Guidelines

### 1. **Keeping Tests Updated**
- Update tests when UI changes
- Add new test cases for new features
- Review tests regularly for relevance

### 2. **Mock Maintenance**
- Regenerate mocks when interfaces change
- Keep mock configurations in sync with real implementations
- Use factory methods for consistent mock data

### 3. **Test Performance**
- Use `pump()` for partial rebuilds
- Use `pumpAndSettle()` for async operations
- Avoid unnecessary rebuilds in tests

## Troubleshooting

### Common Issues

1. **Mock Not Found**
   - Run `flutter packages pub run build_runner build`
   - Check `@GenerateMocks()` annotations
   - Verify imports in test files

2. **Provider Not Found**
   - Ensure provider is imported
   - Check provider overrides in container setup
   - Verify provider is registered in main app

3. **Test Flakiness**
   - Add proper `await` for async operations
   - Use `tester.pumpAndSettle()` for async UI
   - Check for timer/animation issues

4. **Navigation Test Failures**
   - Verify GoRouter configuration
   - Check path parameters extraction
   - Ensure navigation arguments are passed correctly

## Resources

- [Flutter Testing Documentation](https://flutter.dev/docs/testing)
- [Riverpod Testing Guide](https://riverpod.dev/docs/cookbooks/testing)
- [Mockito Package](https://pub.dev/packages/mockito)
- [Widget Testing Best Practices](https://flutter.dev/docs/cookbook/testing/widget/introduction)