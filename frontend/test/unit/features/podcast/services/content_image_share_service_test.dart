import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_conversation_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/services/content_image_share_service.dart';

void main() {
  group('truncateShareContent', () {
    test('does not truncate when content length is within max chars', () {
      final result = truncateShareContent(
        content: 'hello world',
        maxChars: 20,
        truncatedSuffix: 'truncated',
      );

      expect(result, 'hello world');
    });

    test('truncates and appends suffix when content exceeds max chars', () {
      final result = truncateShareContent(
        content: 'abcdefghijklmnopqrstuvwxyz',
        maxChars: 10,
        truncatedSuffix: 'truncated',
      );

      expect(result, 'abcdefghij\n\ntruncated');
    });
  });

  group('formatChatMessagesForShare', () {
    test('formats messages in order with role labels', () {
      final messages = <PodcastConversationMessage>[
        PodcastConversationMessage(
          id: 1,
          role: 'user',
          content: 'What is this episode about?',
          conversationTurn: 1,
          createdAt: DateTime.now().toIso8601String(),
        ),
        PodcastConversationMessage(
          id: 2,
          role: 'assistant',
          content: 'It covers AI model evaluation.',
          conversationTurn: 2,
          createdAt: DateTime.now().toIso8601String(),
        ),
      ];

      final result = formatChatMessagesForShare(
        messages: messages,
        userLabel: 'User',
        assistantLabel: 'Assistant',
      );

      expect(
        result,
        '[User]\nWhat is this episode about?\n\n'
        '[Assistant]\nIt covers AI model evaluation.',
      );
    });
  });

  group('truncateConversationItemsForShare', () {
    test('keeps full conversation when total chars are within limit', () {
      final result = truncateConversationItemsForShare(
        items: const [
          ShareConversationItem(
            roleLabel: 'User',
            content: 'Hello',
            isUser: true,
          ),
          ShareConversationItem(
            roleLabel: 'Assistant',
            content: 'Hi there',
            isUser: false,
          ),
        ],
        maxChars: 20,
        truncatedSuffix: 'truncated',
      );

      expect(result.length, 2);
      expect(result[0].content, 'Hello');
      expect(result[1].content, 'Hi there');
    });

    test('truncates the last included message and appends suffix', () {
      final result = truncateConversationItemsForShare(
        items: const [
          ShareConversationItem(
            roleLabel: 'User',
            content: '12345',
            isUser: true,
          ),
          ShareConversationItem(
            roleLabel: 'Assistant',
            content: 'abcdef',
            isUser: false,
          ),
        ],
        maxChars: 8,
        truncatedSuffix: 'truncated',
      );

      expect(result.length, 2);
      expect(result[0].content, '12345');
      expect(result[1].content, 'abc\n\ntruncated');
    });
  });

  group('extractMarkdownSelection', () {
    test(
      'falls back to selected plain text when no markdown match is found',
      () {
        final result = extractMarkdownSelection(
          markdown: 'Simple summary text',
          selectedText: 'no matching fragment',
        );

        expect(result, 'no matching fragment');
      },
    );

    test('keeps heading marker when selection is inside heading text', () {
      final result = extractMarkdownSelection(
        markdown: '## Episode Highlights\n\nPlain paragraph.',
        selectedText: 'Episode Highlights',
      );

      expect(result, '## Episode Highlights');
    });

    test(
      'keeps list marker and inline markdown when selection is inside list item',
      () {
        final result = extractMarkdownSelection(
          markdown: '## Title\n\n- **Bold** item in list',
          selectedText: 'Bold item in list',
        );

        expect(result, '- **Bold** item in list');
      },
    );

    test(
      'expands to paragraph boundary to preserve inline markdown rendering',
      () {
        final result = extractMarkdownSelection(
          markdown: 'Paragraph with **bold** and `code` token.',
          selectedText: 'bold and code token',
        );

        expect(result, 'Paragraph with **bold** and `code` token.');
      },
    );

    test('expands multi-line selection to full markdown paragraph block', () {
      final result = extractMarkdownSelection(
        markdown:
            'First line with **bold** text.\nSecond line with `code`.\n\nThird paragraph.',
        selectedText: 'bold text. Second line with code.',
      );

      expect(
        result,
        'First line with **bold** text.\nSecond line with `code`.',
      );
    });

    test(
      'expands to full fenced code block when selection intersects code block',
      () {
        final result = extractMarkdownSelection(
          markdown:
              'Intro paragraph.\n\n```dart\nfinal value = 1;\nprint(value);\n```\n\nAfterward.',
          selectedText: 'print(value);',
        );

        expect(result, '```dart\nfinal value = 1;\nprint(value);\n```');
      },
    );

    test(
      'keeps markdown structure when selection uses rendered bullet symbol and compact spacing',
      () {
        final result = extractMarkdownSelection(
          markdown:
              '2. Key insights and takeaways\n- Classic dishes, renewed\n- Flavor innovation',
          selectedText:
              '2.Key insights and takeaways\u2022Classic dishes, renewed',
        );

        expect(
          result,
          '2. Key insights and takeaways\n- Classic dishes, renewed\n- Flavor innovation',
        );
      },
    );
  });
}
