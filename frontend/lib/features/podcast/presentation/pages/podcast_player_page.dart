import 'package:flutter/material.dart';

class PodcastPlayerPage extends StatelessWidget {
  final String? episodeId;

  const PodcastPlayerPage({
    super.key,
    this.episodeId,
  });

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Podcast Player'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
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
              'Podcast Episode Title',
              style: Theme.of(context).textTheme.headlineSmall,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            Text(
              'Podcast Show Name',
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Colors.grey.shade600,
              ),
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