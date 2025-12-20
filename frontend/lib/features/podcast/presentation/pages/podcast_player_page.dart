import 'package:flutter/material.dart';
import '../navigation/podcast_navigation.dart';

class PodcastPlayerPage extends StatelessWidget {
  final PodcastPlayerPageArgs? args;

  const PodcastPlayerPage({
    super.key,
    this.args,
  });

  @override
  Widget build(BuildContext context) {
    final episodeTitle = args?.episodeTitle ?? '未知单集';
    final audioUrl = args?.audioUrl ?? '无音频链接';

    return Scaffold(
      appBar: AppBar(
        title: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.15),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(
              color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
              width: 1,
            ),
          ),
          child: Text(
            episodeTitle,
            style: TextStyle(
              color: Theme.of(context).colorScheme.primary,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
        backgroundColor: Theme.of(context).colorScheme.surface,
        elevation: 2,
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              width: 200,
              height: 200,
              decoration: BoxDecoration(
                color: Colors.grey.shade200,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Icon(
                Icons.audiotrack,
                size: 80,
                color: Colors.grey.shade400,
              ),
            ),
            const SizedBox(height: 24),
            Text(
              episodeTitle,
              style: Theme.of(context).textTheme.headlineSmall,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            Text(
              audioUrl,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Colors.grey.shade600,
              ),
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
            const SizedBox(height: 32),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                IconButton(
                  onPressed: () {
                    // TODO: Rewind
                  },
                  icon: const Icon(Icons.replay_30),
                  iconSize: 32,
                ),
                const SizedBox(width: 16),
                IconButton.filled(
                  onPressed: () {
                    // TODO: Play/Pause
                  },
                  icon: const Icon(Icons.play_arrow),
                  iconSize: 48,
                ),
                const SizedBox(width: 16),
                IconButton(
                  onPressed: () {
                    // TODO: Fast forward
                  },
                  icon: const Icon(Icons.forward_30),
                  iconSize: 32,
                ),
              ],
            ),
            const SizedBox(height: 32),
            const Text(
              'Coming Soon',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.w600,
                color: Colors.orange,
              ),
            ),
          ],
        ),
      ),
    );
  }
}