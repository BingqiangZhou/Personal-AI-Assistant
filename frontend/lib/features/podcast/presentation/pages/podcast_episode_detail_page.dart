import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_html/flutter_html.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../providers/podcast_providers.dart';

class PodcastEpisodeDetailPage extends ConsumerStatefulWidget {
  final int episodeId;

  const PodcastEpisodeDetailPage({
    super.key,
    required this.episodeId,
  });

  @override
  ConsumerState<PodcastEpisodeDetailPage> createState() => _PodcastEpisodeDetailPageState();
}

class _PodcastEpisodeDetailPageState extends ConsumerState<PodcastEpisodeDetailPage>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;
  bool _isGeneratingSummary = false;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final episodeDetailAsync = ref.watch(episodeDetailProvider(widget.episodeId));
    final summaryAsync = ref.watch(podcastSummaryNotifierProvider(widget.episodeId));
    final audioPlayerState = ref.watch(audioPlayerNotifierProvider);

    return Scaffold(
      body: episodeDetailAsync.when(
        data: (episodeDetail) => _buildContent(context, ref, episodeDetail!, audioPlayerState, summaryAsync),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, stack) => _buildErrorState(context, error),
      ),
    );
  }

  Widget _buildContent(
    BuildContext context,
    WidgetRef ref,
    dynamic episodeDetail,
    dynamic audioPlayerState,
    AsyncValue summaryAsync,
  ) {
    final episode = episodeDetail.episode;
    final isCurrentlyPlaying = audioPlayerState.currentEpisode?.id == episode.id;

    return NestedScrollView(
      headerSliverBuilder: (context, innerBoxIsScrolled) {
        return [
          SliverAppBar(
            expandedHeight: 300,
            pinned: true,
            flexibleSpace: FlexibleSpaceBar(
              background: Container(
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                    colors: [
                      Theme.of(context).primaryColor.withOpacity(0.8),
                      Theme.of(context).primaryColor.withOpacity(0.4),
                    ],
                  ),
                ),
                child: Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      // Episode artwork
                      Container(
                        width: 120,
                        height: 120,
                        decoration: BoxDecoration(
                          color: Colors.white.withOpacity(0.2),
                          borderRadius: BorderRadius.circular(16),
                        ),
                        child: Icon(
                          Icons.headphones,
                          size: 60,
                          color: Colors.white,
                        ),
                      ),
                      const SizedBox(height: 16),
                      // Episode title
                      Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 32),
                        child: Text(
                          episode.title,
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 20,
                            fontWeight: FontWeight.bold,
                          ),
                          textAlign: TextAlign.center,
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      const SizedBox(height: 8),
                      // Episode identifier
                      if (episode.episodeIdentifier.isNotEmpty)
                        Text(
                          episode.episodeIdentifier,
                          style: const TextStyle(
                            color: Colors.white70,
                            fontSize: 14,
                          ),
                        ),
                      const SizedBox(height: 8),
                      // Published date
                      Text(
                        DateFormat('MMMM d, yyyy').format(episode.publishedAt),
                        style: const TextStyle(
                          color: Colors.white70,
                          fontSize: 14,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
            actions: [
              IconButton(
                onPressed: () {
                  // TODO: Add to favorites
                },
                icon: const Icon(Icons.favorite_border),
              ),
              PopupMenuButton<String>(
                onSelected: (value) {
                  switch (value) {
                    case 'share':
                      // TODO: Implement share
                      break;
                    case 'download':
                      // TODO: Implement download
                      break;
                  }
                },
                itemBuilder: (context) => [
                  const PopupMenuItem(
                    value: 'share',
                    child: Row(
                      children: [
                        Icon(Icons.share),
                        SizedBox(width: 8),
                        Text('Share Episode'),
                      ],
                    ),
                  ),
                  const PopupMenuItem(
                    value: 'download',
                    child: Row(
                      children: [
                        Icon(Icons.download),
                        SizedBox(width: 8),
                        Text('Download'),
                      ],
                    ),
                  ),
                ],
              ),
            ],
            bottom: TabBar(
              controller: _tabController,
              tabs: const [
                Tab(text: 'Description'),
                Tab(text: 'AI Summary'),
                Tab(text: 'Transcript'),
              ],
            ),
          ),
        ];
      },
      body: TabBarView(
        controller: _tabController,
        children: [
          _buildDescriptionTab(episode),
          _buildSummaryTab(ref, episode, summaryAsync),
          _buildTranscriptTab(episode),
        ],
      ),
      bottomNavigationBar: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surface,
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.1),
              blurRadius: 8,
              offset: const Offset(0, -2),
            ),
          ],
        ),
        child: SafeArea(
          child: Row(
            children: [
              // Play/pause button
              Container(
                decoration: BoxDecoration(
                  color: Theme.of(context).primaryColor,
                  shape: BoxShape.circle,
                ),
                child: IconButton(
                  onPressed: () async {
                    if (isCurrentlyPlaying) {
                      if (audioPlayerState.isPlaying) {
                        await ref.read(audioPlayerNotifierProvider.notifier).pause();
                      } else {
                        await ref.read(audioPlayerNotifierProvider.notifier).resume();
                      }
                    } else {
                      await ref.read(audioPlayerNotifierProvider.notifier).playEpisode(episode);
                    }
                  },
                  icon: Icon(
                    isCurrentlyPlaying
                        ? (audioPlayerState.isPlaying ? Icons.pause : Icons.play_arrow)
                        : Icons.play_arrow,
                    color: Colors.white,
                    size: 32,
                  ),
                ),
              ),
              const SizedBox(width: 16),
              // Episode info
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      episode.title,
                      style: Theme.of(context).textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    const SizedBox(height: 4),
                    Text(
                      episode.formattedDuration,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Colors.grey[600],
                      ),
                    ),
                  ],
                ),
              ),
              // Forward 30 seconds
              IconButton(
                onPressed: () async {
                  final newPosition = (audioPlayerState.position + 30000)
                      .clamp(0, audioPlayerState.duration);
                  await ref.read(audioPlayerNotifierProvider.notifier).seekTo(newPosition);
                },
                icon: const Icon(Icons.forward_30),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDescriptionTab(episode) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Episode metadata
          _buildMetadataRow('Published', DateFormat('MMMM d, yyyy').format(episode.publishedAt)),
          if (episode.audioDuration != null)
            _buildMetadataRow('Duration', episode.formattedDuration),
          if (episode.playCount > 0)
            _buildMetadataRow('Played', '${episode.playCount} time${episode.playCount > 1 ? 's' : ''}'),
          const SizedBox(height: 24),
          // Description
          if (episode.description != null && episode.description!.isNotEmpty) ...[
            Text(
              'Description',
              style: Theme.of(context).textTheme.titleLarge?.copyWith(
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 12),
            Html(
              data: episode.description!,
              style: {
                'body': Style(
                  margin: Margins.zero,
                  padding: HtmlPaddings.zero,
                  fontSize: FontSize(16),
                  lineHeight: const LineHeight(1.5),
                ),
                'p': Style(
                  margin: Margins.only(bottom: 12),
                ),
              },
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildSummaryTab(WidgetRef ref, episode, AsyncValue summaryAsync) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Generate summary button
          if (episode.aiSummary == null) ...[
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: _isGeneratingSummary
                    ? null
                    : () async {
                        setState(() {
                          _isGeneratingSummary = true;
                        });
                        try {
                          await ref
                              .read(podcastSummaryNotifierProvider(widget.episodeId).notifier)
                              .generateSummary();
                        } finally {
                          setState(() {
                            _isGeneratingSummary = false;
                          });
                        }
                      },
                icon: _isGeneratingSummary
                    ? SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          valueColor: AlwaysStoppedAnimation<Color>(
                            Theme.of(context).colorScheme.onPrimary,
                          ),
                        ),
                      )
                    : const Icon(Icons.auto_awesome),
                label: Text(_isGeneratingSummary ? 'Generating...' : 'Generate AI Summary'),
              ),
            ),
            const SizedBox(height: 24),
          ],
          // Summary content
          if (episode.aiSummary != null) ...[
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  'AI Summary',
                  style: Theme.of(context).textTheme.titleLarge?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
                ),
                TextButton.icon(
                  onPressed: _isGeneratingSummary
                      ? null
                      : () async {
                          setState(() {
                            _isGeneratingSummary = true;
                          });
                          try {
                            await ref
                                .read(podcastSummaryNotifierProvider(widget.episodeId).notifier)
                                .generateSummary(forceRegenerate: true);
                          } finally {
                            setState(() {
                              _isGeneratingSummary = false;
                            });
                          }
                        },
                  icon: const Icon(Icons.refresh),
                  label: const Text('Regenerate'),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Theme.of(context).primaryColor.withOpacity(0.1),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: Theme.of(context).primaryColor.withOpacity(0.2),
                ),
              ),
              child: Text(
                episode.aiSummary!,
                style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                  height: 1.6,
                ),
              ),
            ),
            if (episode.summaryVersion != null) ...[
              const SizedBox(height: 8),
              Text(
                'Version: ${episode.summaryVersion}',
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: Colors.grey[600],
                ),
              ),
            ],
          ],
          // Loading state
          if (summaryAsync.isLoading) ...[
            const Center(
              child: Padding(
                padding: EdgeInsets.all(32),
                child: Column(
                  children: [
                    CircularProgressIndicator(),
                    SizedBox(height: 16),
                    Text('Generating AI summary...'),
                  ],
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildTranscriptTab(episode) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (episode.transcriptContent != null) ...[
            Text(
              'Transcript',
              style: Theme.of(context).textTheme.titleLarge?.copyWith(
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 12),
            Text(
              episode.transcriptContent!,
              style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                height: 1.6,
              ),
            ),
          ] else ...[
            Center(
              child: Column(
                children: [
                  Icon(
                    Icons.transcribe,
                    size: 80,
                    color: Colors.grey[400],
                  ),
                  const SizedBox(height: 16),
                  Text(
                    'No Transcript Available',
                    style: Theme.of(context).textTheme.titleLarge?.copyWith(
                      color: Colors.grey[600],
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Transcripts are generated for episodes with audio processing',
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: Colors.grey[500],
                    ),
                    textAlign: TextAlign.center,
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildMetadataRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 100,
            child: Text(
              label,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                fontWeight: FontWeight.w600,
                color: Colors.grey[600],
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: Theme.of(context).textTheme.bodyMedium,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildErrorState(BuildContext context, Object error) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.error_outline,
            size: 80,
            color: Colors.red[400],
          ),
          const SizedBox(height: 16),
          Text(
            'Failed to Load Episode',
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
              color: Colors.red[600],
            ),
          ),
          const SizedBox(height: 8),
          Text(
            error.toString(),
            style: Theme.of(context).textTheme.bodyMedium,
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 32),
          ElevatedButton.icon(
            onPressed: () => Navigator.of(context).pop(),
            icon: const Icon(Icons.arrow_back),
            label: const Text('Go Back'),
          ),
        ],
      ),
    );
  }
}