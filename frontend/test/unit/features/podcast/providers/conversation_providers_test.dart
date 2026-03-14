import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/conversation_providers.dart';

void main() {
  test('releaseConversationProviders removes all cached provider keys', () {
    final conversationProvider = getConversationProvider(3001);
    final sessionListProvider = getSessionListProvider(3001);
    final sessionIdProvider = getCurrentSessionIdProvider(3001);

    expect(conversationStateProviders.containsKey(3001), isTrue);
    expect(sessionListProviders.containsKey(3001), isTrue);
    expect(currentSessionIdProviders.containsKey(3001), isTrue);

    releaseConversationProviders(3001);

    expect(conversationStateProviders.containsKey(3001), isFalse);
    expect(sessionListProviders.containsKey(3001), isFalse);
    expect(currentSessionIdProviders.containsKey(3001), isFalse);

    // Keep references used so analyzer doesn't treat them as dead in test body.
    expect(conversationProvider, isNotNull);
    expect(sessionListProvider, isNotNull);
    expect(sessionIdProvider, isNotNull);
  });
}
