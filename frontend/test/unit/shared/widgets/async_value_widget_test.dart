import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/shared/widgets/async_value_widget.dart';

void main() {
  group('AsyncValueWidget', () {
    group('data state', () {
      testWidgets('renders builder when data is available', (tester) async {
        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: AsyncValueWidget<String>(
                value: const AsyncValue.data('test data'),
                builder: (data) => Text('Data: $data'),
              ),
            ),
          ),
        );

        expect(find.text('Data: test data'), findsOneWidget);
      });

      testWidgets('passes data to builder function', (tester) async {
        const testData = 42;

        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: AsyncValueWidget<int>(
                value: const AsyncValue.data(testData),
                builder: (data) => Text('Count: $data'),
              ),
            ),
          ),
        );

        expect(find.text('Count: 42'), findsOneWidget);
      });
    });

    group('loading state', () {
      testWidgets('renders default loading widget when loading', (tester) async {
        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: AsyncValueWidget<String>(
                value: const AsyncValue.loading(),
                builder: (data) => Text('Data: $data'),
              ),
            ),
          ),
        );

        expect(find.byType(CircularProgressIndicator), findsOneWidget);
      });

      testWidgets('renders custom loading widget when provided', (tester) async {
        const customLoadingKey = Key('custom_loading');

        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: AsyncValueWidget<String>(
                value: const AsyncValue.loading(),
                builder: (data) => Text('Data: $data'),
                loadingWidget: const SizedBox(
                  key: customLoadingKey,
                  child: Text('Loading...'),
                ),
              ),
            ),
          ),
        );

        expect(find.byKey(customLoadingKey), findsOneWidget);
        expect(find.text('Loading...'), findsOneWidget);
      });

      testWidgets('shows data when skipLoadingWhenData is true and has value',
          (tester) async {
        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: AsyncValueWidget<String>(
                value: AsyncValue.data('test').copyWithPrevious(
                  const AsyncValue.data('previous'),
                ),
                builder: (data) => Text('Data: $data'),
                skipLoadingWhenData: true,
              ),
            ),
          ),
        );

        expect(find.text('Data: test'), findsOneWidget);
      });
    });

    group('error state', () {
      testWidgets('renders default error widget when error occurs',
          (tester) async {
        const testError = 'Test error message';

        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: AsyncValueWidget<String>(
                value: AsyncValue.error(testError, StackTrace.empty),
                builder: (data) => Text('Data: $data'),
              ),
            ),
          ),
        );

        expect(find.byIcon(Icons.error_outline), findsOneWidget);
        expect(find.text('An error occurred'), findsOneWidget);
        expect(find.text(testError), findsOneWidget);
      });

      testWidgets('renders custom error builder when provided', (tester) async {
        const testError = 'Test error';
        const customErrorKey = Key('custom_error');

        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: AsyncValueWidget<String>(
                value: AsyncValue.error(testError, StackTrace.empty),
                builder: (data) => Text('Data: $data'),
                errorBuilder: (error, stack) => const SizedBox(
                  key: customErrorKey,
                  child: Text('Custom Error'),
                ),
              ),
            ),
          ),
        );

        expect(find.byKey(customErrorKey), findsOneWidget);
        expect(find.text('Custom Error'), findsOneWidget);
      });
    });
  });

  group('AsyncValueNullableWidget', () {
    group('data state', () {
      testWidgets('renders builder when non-null data is available',
          (tester) async {
        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: AsyncValueNullableWidget<String>(
                value: const AsyncValue.data('test data'),
                builder: (data) => Text('Data: $data'),
              ),
            ),
          ),
        );

        expect(find.text('Data: test data'), findsOneWidget);
      });

      testWidgets('renders default empty widget when data is null',
          (tester) async {
        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: AsyncValueNullableWidget<String>(
                value: const AsyncValue.data(null),
                builder: (data) => Text('Data: $data'),
              ),
            ),
          ),
        );

        expect(find.byIcon(Icons.inbox_outlined), findsOneWidget);
        expect(find.text('No data available'), findsOneWidget);
      });

      testWidgets('renders custom empty builder when provided', (tester) async {
        const customEmptyKey = Key('custom_empty');

        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: AsyncValueNullableWidget<String>(
                value: const AsyncValue.data(null),
                builder: (data) => Text('Data: $data'),
                emptyBuilder: () => const SizedBox(
                  key: customEmptyKey,
                  child: Text('Nothing here'),
                ),
              ),
            ),
          ),
        );

        expect(find.byKey(customEmptyKey), findsOneWidget);
        expect(find.text('Nothing here'), findsOneWidget);
      });
    });

    group('loading state', () {
      testWidgets('renders default loading widget when loading', (tester) async {
        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: AsyncValueNullableWidget<String>(
                value: const AsyncValue.loading(),
                builder: (data) => Text('Data: $data'),
              ),
            ),
          ),
        );

        expect(find.byType(CircularProgressIndicator), findsOneWidget);
      });

      testWidgets('renders custom loading widget when provided', (tester) async {
        const customLoadingKey = Key('custom_loading');

        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: AsyncValueNullableWidget<String>(
                value: const AsyncValue.loading(),
                builder: (data) => Text('Data: $data'),
                loadingWidget: const SizedBox(
                  key: customLoadingKey,
                  child: Text('Loading...'),
                ),
              ),
            ),
          ),
        );

        expect(find.byKey(customLoadingKey), findsOneWidget);
      });
    });

    group('error state', () {
      testWidgets('renders default error widget when error occurs',
          (tester) async {
        const testError = 'Test error message';

        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: AsyncValueNullableWidget<String>(
                value: AsyncValue.error(testError, StackTrace.empty),
                builder: (data) => Text('Data: $data'),
              ),
            ),
          ),
        );

        expect(find.byIcon(Icons.error_outline), findsOneWidget);
        expect(find.text('An error occurred'), findsOneWidget);
      });

      testWidgets('renders custom error builder when provided', (tester) async {
        const customErrorKey = Key('custom_error');

        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: AsyncValueNullableWidget<String>(
                value: AsyncValue.error('error', StackTrace.empty),
                builder: (data) => Text('Data: $data'),
                errorBuilder: (error, stack) => const SizedBox(
                  key: customErrorKey,
                  child: Text('Custom Error'),
                ),
              ),
            ),
          ),
        );

        expect(find.byKey(customErrorKey), findsOneWidget);
      });
    });
  });
}
