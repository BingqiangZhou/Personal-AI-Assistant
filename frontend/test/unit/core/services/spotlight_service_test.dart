import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/services/spotlight_service.dart';

void main() {
  late SpotlightService service;

  setUp(() {
    service = SpotlightService.instance;
  });

  test('singleton instance is not null', () {
    expect(service, isNotNull);
    expect(service, same(SpotlightService.instance));
  });

  test('indexPodcast completes without error', () async {
    await expectLater(
      service.indexPodcast(
        id: 'podcast-1',
        title: 'Test Podcast',
        description: 'A test podcast description',
        imageUrl: 'https://example.com/image.jpg',
      ),
      completes,
    );
  });

  test('indexPodcast completes without optional imageUrl', () async {
    await expectLater(
      service.indexPodcast(
        id: 'podcast-2',
        title: 'Test Podcast',
        description: 'A test podcast description',
      ),
      completes,
    );
  });

  test('indexEpisode completes without error', () async {
    await expectLater(
      service.indexEpisode(
        id: 'episode-1',
        title: 'Test Episode',
        description: 'A test episode description',
        podcastName: 'Test Podcast',
        imageUrl: 'https://example.com/episode.jpg',
      ),
      completes,
    );
  });

  test('indexEpisode completes without optional imageUrl', () async {
    await expectLater(
      service.indexEpisode(
        id: 'episode-2',
        title: 'Test Episode',
        description: 'A test episode description',
        podcastName: 'Test Podcast',
      ),
      completes,
    );
  });

  test('deindexItem completes without error', () async {
    await expectLater(
      service.deindexItem(id: 'item-1'),
      completes,
    );
  });

  test('deindexAll completes without error', () async {
    await expectLater(
      service.deindexAll(),
      completes,
    );
  });
}
