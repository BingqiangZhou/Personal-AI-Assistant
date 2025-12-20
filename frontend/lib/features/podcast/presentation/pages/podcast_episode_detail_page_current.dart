import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../providers/podcast_providers.dart';
import '../../data/models/podcast_episode_model.dart';

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
    final audioPlayerState = ref.watch(audioPlayerProvider);

    return Scaffold(
      body: episodeDetailAsync.when(
        data: (episodeDetail) {
          if (episodeDetail == null) {
            return _buildErrorState(context, 'Episode not found');
          }
          return _buildContent(context, ref, episodeDetail, audioPlayerState);
        },
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, stack) => _buildErrorState(context, error),
      ),
      bottomNavigationBar: _buildBottomBar(context, ref, audioPlayerState),
    );
  }

  Widget _buildContent(
    BuildContext context,
    WidgetRef ref,
    dynamic episodeDetail,
    dynamic audioPlayerState,
  ) {
    final episode = episodeDetail is PodcastEpisodeDetailResponse
        ? episodeDetail.toEpisodeModel()
        : episodeDetail;
    final isCurrentlyPlaying = audioPlayerState.currentEpisode?.id == episode.id;
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;

    return Column(
        children: [
          // Header Section - Left: Logo+Title, Right: Duration
          Container(
            padding: const EdgeInsets.all(20),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Left side: Logo and Title
                Expanded(
                  flex: 7,
                  child: Row(
                    children: [
                      // Logo
                      Container(
                        width: 80,
                        height: 80,
                        decoration: BoxDecoration(
                          borderRadius: BorderRadius.circular(12),
                          boxShadow: [
                            BoxShadow(
                              color: Colors.black.withValues(alpha: 0.2),
                              blurRadius: 10,
                              offset: const Offset(0, 4),
                            ),
                          ],
                        ),
                        child: ClipRRect(
                          borderRadius: BorderRadius.circular(12),
                          child: Container(
                            decoration: BoxDecoration(
                              gradient: LinearGradient(
                                begin: Alignment.topLeft,
                                end: Alignment.bottomRight,
                                colors: [
                                  theme.colorScheme.secondary.withValues(alpha: 0.8),
                                  theme.colorScheme.primary.withValues(alpha: 0.6),
                                ],
                              ),
                            ),
                            child: Icon(
                              Icons.headphones,
                              size: 40,
                              color: Colors.white,
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(width: 16),
                      // Title and subtitle
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              episode.title,
                              style: TextStyle(
                                fontSize: 18,
                                fontWeight: FontWeight.w600,
                                color: theme.colorScheme.onSurface,
                              ),
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                            ),
                            const SizedBox(height: 4),
                            Text(
                              DateFormat('MM月dd日').format(episode.publishedAt),
                              style: TextStyle(
                                fontSize: 14,
                                color: theme.colorScheme.onSurface.withValues(alpha: 0.6),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
                // Right side: Duration
                Expanded(
                  flex: 3,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.end,
                    children: [
                      Text(
                        episode.formattedDuration,
                        style: TextStyle(
                          fontSize: 16,
                          color: theme.colorScheme.onSurface.withValues(alpha: 0.5),
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
      headerSliverBuilder: (context, innerBoxIsScrolled) {
        return [
          SliverAppBar(
            expandedHeight: 320,
            pinned: true,
            backgroundColor: isDark ? theme.colorScheme.surface : Colors.white,
            actions: [
              Container(
                margin: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.2),
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: Colors.white.withValues(alpha: 0.3),
                    width: 1,
                  ),
                ),
                child: IconButton(
                  onPressed: () {},
                  icon: const Icon(Icons.favorite_border, color: Colors.white),
                ),
              ),
            ],
            bottom: TabBar(
              controller: _tabController,
              labelStyle: const TextStyle(
                fontWeight: FontWeight.w600,
                fontSize: 14,
              ),
              indicator: UnderlineTabIndicator(
                borderSide: BorderSide(
                  color: Colors.white,
                  width: 3,
                ),
              ),
              labelColor: Colors.white70,
              unselectedLabelColor: Colors.white30,
              tabs: const [
                Tab(text: 'Description'),
                Tab(text: 'Summary'),
                Tab(text: 'Transcript'),
              ],
            ),
            flexibleSpace: FlexibleSpaceBar(
              background: Container(
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                    colors: [
                      theme.primaryColor.withValues(alpha: 0.9),
                      theme.primaryColor.withValues(alpha: 0.6),
                      theme.primaryColor.withValues(alpha: 0.3),
                    ],
                  ),
                ),
                child: Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Container(
                        width: 140,
                        height: 140,
                        decoration: BoxDecoration(
                          borderRadius: BorderRadius.circular(16),
                          boxShadow: [
                            BoxShadow(
                              color: Colors.black.withValues(alpha: 0.3),
                              blurRadius: 20,
                              offset: const Offset(0, 8),
                            ),
                          ],
                        ),
                        child: ClipRRect(
                          borderRadius: BorderRadius.circular(16),
                          child: Container(
                            decoration: BoxDecoration(
                              gradient: LinearGradient(
                                begin: Alignment.topLeft,
                                end: Alignment.bottomRight,
                                colors: [
                                  theme.colorScheme.secondary.withValues(alpha: 0.8),
                                  theme.colorScheme.primary.withValues(alpha: 0.6),
                                ],
                              ),
                            ),
                            child: Icon(
                              Icons.headphones,
                              size: 70,
                              color: Colors.white,
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(height: 16),
                      Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 32),
                        child: Text(
                          episode.title,
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 20,
                            fontWeight: FontWeight.bold,
                            shadows: [
                              Shadow(
                                offset: Offset(0, 2),
                                blurRadius: 4,
                                color: Colors.black26,
                              ),
                            ],
                          ),
                          textAlign: TextAlign.center,
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      const SizedBox(height: 16),
                      // Enhanced metadata tags
                      Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          // Date
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                            decoration: BoxDecoration(
                              color: Colors.black.withValues(alpha: 0.3),
                              borderRadius: BorderRadius.circular(12),
                              border: Border.all(
                                color: Colors.white.withValues(alpha: 0.2),
                                width: 1,
                              ),
                            ),
                            child: Text(
                              DateFormat('MM月dd日').format(episode.publishedAt),
                              style: const TextStyle(
                                color: Colors.white,
                                fontSize: 12,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                          ),
                          const SizedBox(width: 8),
                          // Duration
                          if (episode.audioDuration != null)
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                              decoration: BoxDecoration(
                                color: Colors.black.withValues(alpha: 0.3),
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(
                                  color: Colors.white.withValues(alpha: 0.2),
                                  width: 1,
                                ),
                              ),
                              child: Text(
                                episode.formattedDuration,
                                style: const TextStyle(
                                  color: Colors.white,
                                  fontSize: 12,
                                  fontWeight: FontWeight.w500,
                                ),
                              ),
                            ),
                          const SizedBox(width: 8),
                          // Episode identifier
                          if (episode.episodeIdentifier.isNotEmpty)
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                              decoration: BoxDecoration(
                                color: theme.colorScheme.secondary.withValues(alpha: 0.8),
                                borderRadius: BorderRadius.circular(12),
                              ),
                              child: Text(
                                episode.episodeIdentifier,
                                style: const TextStyle(
                                  color: Colors.white,
                                  fontSize: 12,
                                  fontWeight: FontWeight.w500,
                                ),
                              ),
                            ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ];
      },
      body: Column(
        children: [
          // Progress Bar Section
          Container(
            decoration: BoxDecoration(
              color: isDark ? theme.colorScheme.surface : Colors.white,
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: 0.1),
                  blurRadius: 4,
                  offset: const Offset(0, 2),
                ),
              ],
            ),
            padding: const EdgeInsets.all(20),
            child: Column(
              children: [
                // Progress bar
                Row(
                  children: [
                    // Current time
                    Text(
                      '00:00',
                      style: TextStyle(
                        color: theme.colorScheme.onSurface.withValues(alpha: 0.7),
                        fontSize: 12,
                      ),
                    ),
                    const SizedBox(width: 16),
                    // Progress bar
                    Expanded(
                      child: GestureDetector(
                        onTap: () {},
                        child: Container(
                          height: 4,
                          decoration: BoxDecoration(
                            color: theme.colorScheme.outline.withValues(alpha: 0.3),
                            borderRadius: BorderRadius.circular(2),
                          ),
                          child: FractionallySizedBox(
                            alignment: Alignment.centerLeft,
                            widthFactor: 0.0, // This will be updated with actual progress
                            child: Container(
                              decoration: BoxDecoration(
                                color: theme.primaryColor,
                                borderRadius: BorderRadius.circular(2),
                              ),
                            ),
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(width: 16),
                    // Total time
                    Text(
                      episode.formattedDuration,
                      style: TextStyle(
                        color: theme.colorScheme.onSurface.withValues(alpha: 0.7),
                        fontSize: 12,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                // Playback controls
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    // Skip back
                    IconButton(
                      onPressed: () {},
                      icon: Icon(
                        Icons.replay_30,
                        color: theme.colorScheme.onSurface,
                        size: 32,
                      ),
                    ),
                    // Previous
                    IconButton(
                      onPressed: () {},
                      icon: Icon(
                        Icons.skip_previous,
                        color: theme.colorScheme.onSurface,
                        size: 32,
                      ),
                    ),
                    // Play/Pause
                    Container(
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: theme.primaryColor,
                      ),
                      child: IconButton(
                        onPressed: () {},
                        icon: Icon(
                          Icons.play_arrow,
                          color: Colors.white,
                          size: 32,
                        ),
                      ),
                    ),
                    // Next
                    IconButton(
                      onPressed: () {},
                      icon: Icon(
                        Icons.skip_next,
                        color: theme.colorScheme.onSurface,
                        size: 32,
                      ),
                    ),
                    // Skip forward
                    IconButton(
                      onPressed: () {},
                      icon: Icon(
                        Icons.forward_30,
                        color: theme.colorScheme.onSurface,
                        size: 32,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
          // Tab content
          Expanded(
            child: Container(
              color: isDark ? theme.colorScheme.surface : Colors.grey[50],
              child: TabBarView(
                controller: _tabController,
                children: [
                  _buildDescriptionTab(episode),
                  _buildSummaryTab(episode),
                  _buildTranscriptTab(episode),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBottomBar(
    BuildContext context,
    WidgetRef ref,
    dynamic audioPlayerState,
  ) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
      decoration: BoxDecoration(
        color: isDark
            ? theme.colorScheme.surface.withValues(alpha: 0.95)
            : theme.colorScheme.surface,
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.2),
            blurRadius: 12,
            offset: const Offset(0, -4),
          ),
        ],
        border: Border(
          top: BorderSide(
            color: isDark
                ? theme.dividerColor.withValues(alpha: 0.3)
                : theme.dividerColor,
            width: 1,
          ),
        ),
      ),
      child: SafeArea(
        child: Row(
          children: [
            // Previous button
            Container(
              decoration: BoxDecoration(
                color: theme.colorScheme.surface.withValues(alpha: 0.6),
                borderRadius: BorderRadius.circular(24),
                border: Border.all(
                  color: theme.colorScheme.outline.withValues(alpha: 0.3),
                  width: 1.5,
                ),
              ),
              child: IconButton(
                onPressed: () {},
                icon: Icon(
                  Icons.skip_previous,
                  color: theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.9),
                  size: 28,
                ),
              ),
            ),
            const SizedBox(width: 16),
            // Rewind button
            Container(
              decoration: BoxDecoration(
                color: theme.colorScheme.surface.withValues(alpha: 0.6),
                borderRadius: BorderRadius.circular(24),
                border: Border.all(
                  color: theme.colorScheme.outline.withValues(alpha: 0.3),
                  width: 1.5,
                ),
              ),
              child: IconButton(
                onPressed: () {},
                icon: Icon(
                  Icons.fast_rewind,
                  color: theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.9),
                  size: 28,
                ),
              ),
            ),
            const SizedBox(width: 16),
            // Play/Pause button
            Container(
              width: 64,
              height: 64,
              decoration: BoxDecoration(
                color: theme.primaryColor,
                shape: BoxShape.circle,
                boxShadow: [
                  BoxShadow(
                    color: theme.primaryColor.withValues(alpha: 0.4),
                    blurRadius: 16,
                    offset: const Offset(0, 4),
                  ),
                ],
                border: Border.all(
                  color: theme.primaryColor.withValues(alpha: 0.5),
                  width: 2,
                ),
              ),
              child: IconButton(
                onPressed: () {},
                icon: Icon(
                  Icons.play_arrow,
                  color: theme.colorScheme.onPrimary,
                  size: 32,
                ),
              ),
            ),
            const SizedBox(width: 16),
            // Forward button
            Container(
              decoration: BoxDecoration(
                color: theme.colorScheme.surface.withValues(alpha: 0.6),
                borderRadius: BorderRadius.circular(24),
                border: Border.all(
                  color: theme.colorScheme.outline.withValues(alpha: 0.3),
                  width: 1.5,
                ),
              ),
              child: IconButton(
                onPressed: () {},
                icon: Icon(
                  Icons.fast_forward,
                  color: theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.9),
                  size: 28,
                ),
              ),
            ),
            const SizedBox(width: 16),
            // Next button
            Container(
              decoration: BoxDecoration(
                color: theme.colorScheme.surface.withValues(alpha: 0.6),
                borderRadius: BorderRadius.circular(24),
                border: Border.all(
                  color: theme.colorScheme.outline.withValues(alpha: 0.3),
                  width: 1.5,
                ),
              ),
              child: IconButton(
                onPressed: () {},
                icon: Icon(
                  Icons.skip_next,
                  color: theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.9),
                  size: 28,
                ),
              ),
            ),
            const SizedBox(width: 24),
            // Speed control
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: theme.colorScheme.secondaryContainer.withValues(alpha: 0.3),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: theme.colorScheme.secondary.withValues(alpha: 0.3),
                  width: 1,
                ),
              ),
              child: Text(
                '1.0x',
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: theme.colorScheme.onSecondaryContainer.withValues(alpha: 0.9),
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDescriptionTab(dynamic episode) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Container(
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          color: isDark
              ? theme.colorScheme.surface.withValues(alpha: 0.7)
              : Colors.white,
          borderRadius: BorderRadius.circular(12),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.1),
              blurRadius: 8,
              offset: const Offset(0, 2),
            ),
          ],
          border: Border.all(
            color: isDark
                ? theme.dividerColor.withValues(alpha: 0.3)
                : Colors.grey.withValues(alpha: 0.3),
            width: 1,
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              decoration: BoxDecoration(
                color: theme.primaryColor.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                  color: theme.primaryColor.withValues(alpha: 0.3),
                  width: 1,
                ),
              ),
              child: Text(
                'Description',
                style: Theme.of(context).textTheme.titleLarge?.copyWith(
                      fontWeight: FontWeight.bold,
                      color: theme.primaryColor.withValues(alpha: 0.9),
                    ),
              ),
            ),
            const SizedBox(height: 16),
            Text(
              episode.description ?? 'No description available',
              style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                    height: 1.6,
                    color: isDark
                        ? theme.colorScheme.onSurface.withValues(alpha: 0.9)
                        : Colors.black87,
                    fontSize: 16,
                  ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSummaryTab(dynamic episode) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Container(
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          color: isDark
              ? theme.colorScheme.surface.withValues(alpha: 0.7)
              : Colors.white,
          borderRadius: BorderRadius.circular(12),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.1),
              blurRadius: 8,
              offset: const Offset(0, 2),
            ),
          ],
          border: Border.all(
            color: isDark
                ? theme.dividerColor.withValues(alpha: 0.3)
                : Colors.grey.withValues(alpha: 0.3),
            width: 1,
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              decoration: BoxDecoration(
                color: theme.colorScheme.tertiary.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                  color: theme.colorScheme.tertiary.withValues(alpha: 0.3),
                  width: 1,
                ),
              ),
              child: Text(
                'AI Summary',
                style: Theme.of(context).textTheme.titleLarge?.copyWith(
                      fontWeight: FontWeight.bold,
                      color: theme.colorScheme.onTertiary.withValues(alpha: 0.9),
                    ),
              ),
            ),
            const SizedBox(height: 16),
            if (episode.aiSummary != null)
              Text(
                episode.aiSummary,
                style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                      height: 1.6,
                      color: isDark
                          ? theme.colorScheme.onSurface.withValues(alpha: 0.9)
                          : Colors.black87,
                      fontSize: 16,
                    ),
              )
            else
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.orange.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: Colors.orange.withValues(alpha: 0.3),
                    width: 1,
                  ),
                ),
                child: Text(
                  'No summary available yet',
                  style: TextStyle(
                    color: Colors.orange.shade700,
                    fontWeight: FontWeight.w500,
                    fontSize: 16,
                  ),
                  textAlign: TextAlign.center,
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildTranscriptTab(dynamic episode) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Container(
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          color: isDark
              ? theme.colorScheme.surface.withValues(alpha: 0.7)
              : Colors.white,
          borderRadius: BorderRadius.circular(12),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.1),
              blurRadius: 8,
              offset: const Offset(0, 2),
            ),
          ],
          border: Border.all(
            color: isDark
                ? theme.dividerColor.withValues(alpha: 0.3)
                : Colors.grey.withValues(alpha: 0.3),
            width: 1,
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              decoration: BoxDecoration(
                color: theme.colorScheme.secondary.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                  color: theme.colorScheme.secondary.withValues(alpha: 0.3),
                  width: 1,
                ),
              ),
              child: Text(
                'Transcript',
                style: Theme.of(context).textTheme.titleLarge?.copyWith(
                      fontWeight: FontWeight.bold,
                      color: theme.colorScheme.onSecondary.withValues(alpha: 0.9),
                    ),
              ),
            ),
            const SizedBox(height: 16),
            if (episode.transcriptContent != null)
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.grey.withValues(alpha: 0.05),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: Colors.grey.withValues(alpha: 0.2),
                    width: 1,
                  ),
                ),
                child: Text(
                  episode.transcriptContent,
                  style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                        fontFamily: 'monospace',
                        height: 1.5,
                        color: isDark
                            ? theme.colorScheme.onSurface.withValues(alpha: 0.9)
                            : Colors.black87,
                      ),
                ),
              )
            else
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.blue.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.all(Radius.circular(8)),
                  border: Border.all(
                    color: Colors.blue.withValues(alpha: 0.3),
                    width: 1,
                  ),
                ),
                child: Text(
                  'No transcript available',
                  style: TextStyle(
                    color: Colors.blue.shade700,
                    fontWeight: FontWeight.w500,
                    fontSize: 16,
                  ),
                  textAlign: TextAlign.center,
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildErrorState(BuildContext context, dynamic error) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(
            Icons.error_outline,
            size: 64,
            color: Colors.red,
          ),
          const SizedBox(height: 16),
          Text(
            'Error loading episode',
            style: Theme.of(context).textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 32),
            child: Text(
              error.toString(),
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Colors.grey[600],
                  ),
            ),
          ),
          const SizedBox(height: 24),
          ElevatedButton(
            onPressed: () {
              context.pop();
            },
            child: const Text('Go Back'),
          ),
        ],
      ),
    );
  }
}
