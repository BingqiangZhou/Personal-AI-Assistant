import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import '../../data/models/podcast_episode_model.dart';
import '../providers/podcast_providers.dart';
import 'speed_ruler/speed_roller_picker.dart';

/// Floating podcast player on the right side of the screen
/// with collapsed and expanded states
class SideFloatingPlayerWidget extends ConsumerStatefulWidget {
  const SideFloatingPlayerWidget({super.key});

  @override
  ConsumerState<SideFloatingPlayerWidget> createState() =>
      _SideFloatingPlayerWidgetState();
}

class _SideFloatingPlayerWidgetState
    extends ConsumerState<SideFloatingPlayerWidget>
    with SingleTickerProviderStateMixin {
  late AnimationController _animationController;
  late Animation<double> _widthAnimation;
  bool _isExpanded = false;
  final GlobalKey _playerKey = GlobalKey();

  // Draggable position state
  Offset _playerOffset = Offset.zero;
  Offset _savedCollapsedOffset = Offset.zero; // Save position when expanding
  Offset _dragStartOffset = Offset.zero;
  Offset _dragStartPosition = Offset.zero;

  @override
  void initState() {
    super.initState();
    _animationController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 300),
    );
    _widthAnimation = CurvedAnimation(
      parent: _animationController,
      curve: Curves.easeInOut,
    );
    // Initialize position after first frame
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _initializePosition();
    });
  }

  void _initializePosition() {
    final screenWidth = MediaQuery.of(context).size.width;
    final screenHeight = MediaQuery.of(context).size.height;
    final isMobile = screenWidth < 600;

    // For desktop expanded: position at right edge center, expand inward
    if (_isExpanded && !isMobile) {
      final expandedWidth = 320.0;
      final right = 24.0;
      final top = (screenHeight - 400) / 2; // Center vertically, assuming ~400px height

      setState(() {
        // Position from right edge, expand to the left
        _playerOffset = Offset(screenWidth - right - expandedWidth, top);
      });
      return;
    }

    // Default position: right side, vertically centered (or bottom for mobile)
    final right = isMobile ? 16.0 : 24.0;
    final top = isMobile ? screenHeight - 480 : (screenHeight - 200) / 2;

    setState(() {
      _playerOffset = Offset(screenWidth - right - 64, top);
    });
  }

  /// Snap position to nearest edge
  /// Desktop collapsed: Only X axis snaps to RIGHT edge, Y axis stays free
  /// Mobile collapsed: Snaps to closest edge (top, bottom, left, right)
  /// Expanded state: No snapping (uses fixed position)
  Offset _snapToEdge(Offset position, double playerWidth, double playerHeight, double screenWidth, double screenHeight, bool isDesktop, bool isCollapsed) {
    // Desktop collapsed: Snap X to right edge only, keep Y free
    if (isDesktop && isCollapsed) {
      final newX = screenWidth - playerWidth - 24; // 24dp from right edge
      // Clamp Y to screen bounds with margin
      final minY = 16.0;
      final maxY = screenHeight - playerHeight - 16;
      final clampedY = position.dy.clamp(minY, maxY);
      return Offset(newX, clampedY);
    }

    // Mobile: Allow snapping to all four edges
    // Calculate distances to all four edges
    final distanceToLeft = position.dx;
    final distanceToRight = screenWidth - position.dx - playerWidth;
    final distanceToTop = position.dy;
    final distanceToBottom = screenHeight - position.dy - playerHeight;

    // Find the minimum distance
    final minDistance = [
      distanceToLeft,
      distanceToRight,
      distanceToTop,
      distanceToBottom,
    ].reduce((a, b) => a < b ? a : b);

    // Snap to the closest edge
    double newX = position.dx;
    double newY = position.dy;

    if (minDistance == distanceToLeft) {
      newX = 16; // Snap to left edge
    } else if (minDistance == distanceToRight) {
      newX = screenWidth - playerWidth - 16; // Snap to right edge
    } else if (minDistance == distanceToTop) {
      newY = 16; // Snap to top edge
    } else if (minDistance == distanceToBottom) {
      newY = screenHeight - playerHeight - 16; // Snap to bottom edge
    }

    return Offset(newX, newY);
  }

  @override
  void dispose() {
    _animationController.dispose();
    super.dispose();
  }

  void _toggleExpand() {
    setState(() {
      _isExpanded = !_isExpanded;
      if (_isExpanded) {
        // Save current position before expanding
        _savedCollapsedOffset = _playerOffset;
        _animationController.forward();
        // No need to change _playerOffset - expanded state uses fixed right positioning
      } else {
        _animationController.reverse();
        // Restore saved position when collapsing
        _playerOffset = _savedCollapsedOffset;
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final audioPlayerState = ref.watch(audioPlayerProvider);
    final l10n = AppLocalizations.of(context);

    // Don't show if no episode is loaded
    if (audioPlayerState.currentEpisode == null) {
      return const SizedBox.shrink();
    }

    final screenWidth = MediaQuery.of(context).size.width;
    final screenHeight = MediaQuery.of(context).size.height;
    final bottomPadding = MediaQuery.of(context).padding.bottom;
    final isMobile = screenWidth < 600;
    final isTablet = screenWidth >= 600 && screenWidth < 840;

    // Calculate dimensions
    final collapsedWidth = 64.0;
    final expandedWidth = isMobile
        ? screenWidth - 32
        : (isTablet ? 280.0 : 320.0);

    // Calculate top position and max height
    final topPosition = _getTopPosition(context, isMobile);
    final bottomNavHeight = 60.0 + bottomPadding; // Standard bottom nav height + safe area
    final bottomSpacing = 2.0; // Spacing from bottom nav when expanded

    return Stack(
      children: [
        // Full-screen overlay when expanded (dimmed background)
        if (_isExpanded)
          Container(
            color: Colors.black.withValues(alpha: 0.3),
          ),

        // Tap detector - wraps everything and handles outside taps
        Positioned.fill(
          child: Listener(
            behavior: HitTestBehavior.translucent,
            onPointerDown: (event) {
              if (!_isExpanded) return;

              // Get player position using GlobalKey
              final RenderBox? playerBox =
                  _playerKey.currentContext?.findRenderObject() as RenderBox?;
              if (playerBox == null) {
                _toggleExpand();
                return;
              }

              // Get player bounds
              final playerPosition = playerBox.localToGlobal(Offset.zero);
              final playerSize = playerBox.size;

              // Check if tap is outside player bounds
              final tapX = event.position.dx;
              final tapY = event.position.dy;

              final isOutside = tapX < playerPosition.dx ||
                  tapX > playerPosition.dx + playerSize.width ||
                  tapY < playerPosition.dy ||
                  tapY > playerPosition.dy + playerSize.height;

              if (isOutside) {
                _toggleExpand();
              }
              // If tap is inside player, let the player's own gesture handlers handle it
            },
            child: IgnorePointer(
              // Ignore pointer events so they pass through to children
              child: Container(
                color: Colors.transparent,
              ),
            ),
          ),
        ),

        // Actual floating player widget
        // Use different positioning for mobile expanded state vs others
        isMobile && _isExpanded
            ? Positioned(
                key: _playerKey,
                right: 16,
                bottom: bottomNavHeight + bottomSpacing,
                width: screenWidth - 32,
                height: screenHeight - topPosition - bottomNavHeight - bottomSpacing,
                child: _buildPlayerContent(
                  context,
                  ref,
                  audioPlayerState,
                  l10n,
                  isMobile,
                  isTablet,
                  collapsedWidth,
                  expandedWidth,
                  screenHeight,
                ),
              )
            : (_isExpanded && !isMobile)
                ? Positioned(
                    key: _playerKey,
                    right: 24, // Fixed to right edge
                    top: (screenHeight - 450) / 2, // Vertically centered, assuming ~450px height
                    child: _buildPlayerContent(
                      context,
                      ref,
                      audioPlayerState,
                      l10n,
                      isMobile,
                      isTablet,
                      collapsedWidth,
                      expandedWidth,
                      screenHeight,
                    ),
                  )
                : Positioned(
                    key: _playerKey,
                    left: _playerOffset.dx,
                    top: _playerOffset.dy,
                    child: GestureDetector(
                      // Desktop collapsed: Enable drag (but only on right edge)
                      // Mobile collapsed: Enable drag (can snap to any edge)
                      // Expanded: Disable drag (uses fixed position)
                      onPanStart: (details) {
                        setState(() {
                          _dragStartOffset = details.globalPosition;
                          _dragStartPosition = _playerOffset;
                        });
                      },
                      onPanUpdate: (details) {
                        setState(() {
                          final deltaX = details.globalPosition.dx - _dragStartOffset.dx;
                          final deltaY = details.globalPosition.dy - _dragStartOffset.dy;
                          _playerOffset = Offset(
                            _dragStartPosition.dx + deltaX,
                            _dragStartPosition.dy + deltaY,
                          );
                        });
                      },
                      onPanEnd: (details) {
                        setState(() {
                          // Calculate player size for snapping
                          final currentWidth = collapsedWidth;
                          final playerHeight = 64.0;
                          // Snap to edge
                          _playerOffset = _snapToEdge(
                            _playerOffset,
                            currentWidth,
                            playerHeight,
                            screenWidth,
                            screenHeight,
                            !isMobile, // isDesktop
                            true, // isCollapsed
                          );
                        });
                      },
                      child: _buildPlayerContent(
                        context,
                        ref,
                        audioPlayerState,
                        l10n,
                        isMobile,
                        isTablet,
                        collapsedWidth,
                        expandedWidth,
                        screenHeight,
                      ),
                    ),
                  ),
      ],
    );
  }

  Widget _buildPlayerContent(
    BuildContext context,
    WidgetRef ref,
    dynamic audioPlayerState,
    AppLocalizations? l10n,
    bool isMobile,
    bool isTablet,
    double collapsedWidth,
    double expandedWidth,
    double screenHeight,
  ) {
    return AnimatedBuilder(
      animation: _widthAnimation,
      builder: (context, child) {
        final currentWidth =
            collapsedWidth + (expandedWidth - collapsedWidth) * _widthAnimation.value;

        // Calculate max height - only for non-mobile-expanded cases
        final maxHeight = !(isMobile && _isExpanded)
            ? screenHeight * 0.8
            : double.infinity;

        return Container(
          width: currentWidth,
          constraints: BoxConstraints(
            maxHeight: maxHeight,
          ),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surface,
            borderRadius: BorderRadius.circular(16),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.2),
                blurRadius: _isExpanded ? 16 : 8,
                offset: const Offset(0, 4),
              ),
            ],
          ),
          child: ClipRRect(
            borderRadius: BorderRadius.circular(16),
            child: _isExpanded
                ? _ExpandedPlayerContent(
                    episode: audioPlayerState.currentEpisode!,
                    isPlaying: audioPlayerState.isPlaying,
                    isLoading: audioPlayerState.isLoading,
                    position: audioPlayerState.position,
                    duration: audioPlayerState.duration,
                    playbackRate: audioPlayerState.playbackRate,
                    onCollapse: _toggleExpand,
                    onClose: () => _closePlayer(ref),
                    onPlayPause: () => _handlePlayPause(ref, audioPlayerState.isPlaying),
                    onSeek: (position) => ref.read(audioPlayerProvider.notifier).seekTo(position),
                    onRewind: () => _handleRewind(ref, audioPlayerState),
                    onForward: () => _handleForward(ref, audioPlayerState),
                    onSpeedChange: (speed) => ref.read(audioPlayerProvider.notifier).setPlaybackRate(speed),
                    onNavigateToEpisode: () => _navigateToEpisode(audioPlayerState.currentEpisode!),
                    l10n: l10n,
                  )
                : _CollapsedPlayerContent(
                    episode: audioPlayerState.currentEpisode!,
                    isPlaying: audioPlayerState.isPlaying,
                    isLoading: audioPlayerState.isLoading,
                    onExpand: _toggleExpand,
                    onPlayPause: () => _handlePlayPause(ref, audioPlayerState.isPlaying),
                    onNavigateToEpisode: () => _navigateToEpisode(audioPlayerState.currentEpisode!),
                  ),
          ),
        );
      },
    );
  }

  double _getTopPosition(BuildContext context, bool isMobile) {
    if (isMobile) {
      return MediaQuery.of(context).size.height - 480;
    }
    return (MediaQuery.of(context).size.height - 200) / 2;
  }

  void _handlePlayPause(WidgetRef ref, bool isPlaying) {
    final notifier = ref.read(audioPlayerProvider.notifier);
    if (isPlaying) {
      notifier.pause();
    } else {
      notifier.resume();
    }
  }

  void _handleRewind(WidgetRef ref, dynamic audioPlayerState) {
    final newPosition = (audioPlayerState.position - 10000)
        .clamp(0, audioPlayerState.duration);
    ref.read(audioPlayerProvider.notifier).seekTo(newPosition);
  }

  void _handleForward(WidgetRef ref, dynamic audioPlayerState) {
    final newPosition = (audioPlayerState.position + 30000)
        .clamp(0, audioPlayerState.duration);
    ref.read(audioPlayerProvider.notifier).seekTo(newPosition);
  }

  void _navigateToEpisode(PodcastEpisodeModel episode) {
    context.push('/podcast/episode/detail/${episode.id}');
  }

  void _closePlayer(WidgetRef ref) {
    // Stop playback and clear the current episode
    ref.read(audioPlayerProvider.notifier).stop();
  }
}

/// Collapsed state content
class _CollapsedPlayerContent extends StatelessWidget {
  final PodcastEpisodeModel episode;
  final bool isPlaying;
  final bool isLoading;
  final VoidCallback onExpand;
  final VoidCallback onPlayPause;
  final VoidCallback onNavigateToEpisode;

  const _CollapsedPlayerContent({
    required this.episode,
    required this.isPlaying,
    required this.isLoading,
    required this.onExpand,
    required this.onPlayPause,
    required this.onNavigateToEpisode,
  });

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        // Expand button at top
        Tooltip(
          message: l10n?.podcast_player_expand ?? 'Expand',
          child: Material(
            color: Colors.transparent,
            child: InkWell(
              onTap: onExpand,
              child: Container(
                width: 64,
                height: 40,
                decoration: BoxDecoration(
                  color: Colors.black.withValues(alpha: 0.3),
                ),
                child: const Icon(
                  Icons.chevron_left,
                  color: Colors.white,
                  size: 24,
                ),
              ),
            ),
          ),
        ),

        // Play/Pause button with podcast image background
        Padding(
          padding: const EdgeInsets.all(8),
          child: Tooltip(
            message: isPlaying
                ? (l10n?.podcast_player_pause ?? 'Pause')
                : (l10n?.podcast_player_play ?? 'Play'),
            child: Material(
              color: Colors.transparent,
              child: InkWell(
                onTap: onPlayPause,
                onLongPress: onNavigateToEpisode,
                child: Container(
                  width: 48,
                  height: 48,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                  ),
                  clipBehavior: Clip.antiAlias,
                  child: Stack(
                    fit: StackFit.expand,
                    children: [
                      // Podcast image as background
                      _buildPodcastImageForButton(context),
                      // Semi-transparent overlay
                      Container(
                        color: Colors.black.withValues(alpha: 0.3),
                      ),
                      // Play/Pause icon
                      Center(
                        child: isLoading
                            ? const SizedBox(
                                width: 20,
                                height: 20,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                                ),
                              )
                            : Icon(
                                isPlaying ? Icons.pause : Icons.play_arrow,
                                color: Colors.white,
                                size: 28,
                              ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildPodcastImageForButton(BuildContext context) {
    final imageUrl = episode.subscriptionImageUrl ?? episode.imageUrl;

    if (imageUrl != null && imageUrl.isNotEmpty) {
      return Image.network(
        imageUrl,
        fit: BoxFit.cover,
        errorBuilder: (context, error, stackTrace) {
          return _buildDefaultCoverForButton(context);
        },
        loadingBuilder: (context, child, loadingProgress) {
          if (loadingProgress == null) return child;
          return _buildLoadingCoverForButton(context);
        },
      );
    }

    return _buildDefaultCoverForButton(context);
  }

  Widget _buildDefaultCoverForButton(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            Theme.of(context).colorScheme.primary,
            Theme.of(context).colorScheme.secondary,
          ],
        ),
      ),
    );
  }

  Widget _buildLoadingCoverForButton(BuildContext context) {
    return Container(
      color: Theme.of(context).colorScheme.surfaceContainerHighest,
    );
  }
}

/// Expanded state content
class _ExpandedPlayerContent extends StatefulWidget {
  final PodcastEpisodeModel episode;
  final bool isPlaying;
  final bool isLoading;
  final int position;
  final int duration;
  final double playbackRate;
  final VoidCallback onCollapse;
  final VoidCallback onClose;
  final VoidCallback onPlayPause;
  final void Function(int) onSeek;
  final VoidCallback onRewind;
  final VoidCallback onForward;
  final void Function(double) onSpeedChange;
  final VoidCallback onNavigateToEpisode;
  final AppLocalizations? l10n;

  const _ExpandedPlayerContent({
    required this.episode,
    required this.isPlaying,
    required this.isLoading,
    required this.position,
    required this.duration,
    required this.playbackRate,
    required this.onCollapse,
    required this.onClose,
    required this.onPlayPause,
    required this.onSeek,
    required this.onRewind,
    required this.onForward,
    required this.onSpeedChange,
    required this.onNavigateToEpisode,
    required this.l10n,
  });

  @override
  State<_ExpandedPlayerContent> createState() => _ExpandedPlayerContentState();
}

class _ExpandedPlayerContentState extends State<_ExpandedPlayerContent> {
  final GlobalKey _speedButtonKey = GlobalKey();

  @override
  Widget build(BuildContext context) {
    // ... 其他代码保持不变
    return Material(
      color: Colors.transparent,
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Header: "正在播放" + Collapse button
            _buildHeader(context),

            // Episode info
            _buildEpisodeInfo(context),

            const SizedBox(height: 16),

            // Progress bar
            _buildProgressBar(context),

            const SizedBox(height: 16),

            // Playback controls
            _buildPlaybackControls(context),

            const SizedBox(height: 16),

            // Options row
            _buildOptionsRow(context),

            const SizedBox(height: 16),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    if (l10n == null) {
      return const SizedBox.shrink();
    }

    // Use LayoutBuilder to detect available width
    return LayoutBuilder(
      builder: (context, constraints) {
        // Minimum width: padding (12*2) + two buttons (40*2) + spacing (8*2) = 24 + 80 + 16 = 120
        // Adding safety margin to prevent edge cases
        final minWidthForHeader = 130.0;

        // If width is too small (during animation), hide the header
        if (constraints.maxWidth < minWidthForHeader) {
          return const SizedBox.shrink();
        }

        // Calculate available width for content after padding
        final contentWidth = constraints.maxWidth - 24; // 24 = padding horizontal (12*2)

        // Minimum width for showing title: buttons (80) + spacing (16) + some space for text (60)
        final minWidthForTitle = 160.0;
        final showTitle = contentWidth >= minWidthForTitle;

        return Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
            border: Border(
              bottom: BorderSide(
                color: Theme.of(context).colorScheme.outlineVariant,
                width: 1,
              ),
            ),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.max,
            children: [
              // Close button on the left
              SizedBox(
                width: 40,
                height: 40,
                child: IconButton(
                  icon: const Icon(Icons.close),
                  iconSize: 20,
                  onPressed: widget.onClose,
                  padding: EdgeInsets.zero,
                  tooltip: 'Close',
                ),
              ),
              // Only show spacing and title if width allows
              if (showTitle) const SizedBox(width: 8),
              // "正在播放" title in the center - only show if width allows
              if (showTitle)
                Expanded(
                  child: Text(
                    l10n.podcast_player_now_playing,
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                      color: Theme.of(context).colorScheme.onSurface,
                    ),
                    overflow: TextOverflow.ellipsis,
                    maxLines: 1,
                    textAlign: TextAlign.center,
                  ),
                ),
              if (showTitle) const SizedBox(width: 8),
              // Add spacer if title is hidden
              if (!showTitle) const Spacer(),
              // Collapse button on the right
              SizedBox(
                width: 40,
                height: 40,
                child: IconButton(
                  icon: const Icon(Icons.chevron_right),
                  iconSize: 20,
                  onPressed: widget.onCollapse,
                  padding: EdgeInsets.zero,
                  tooltip: l10n.podcast_player_collapse,
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildEpisodeInfo(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        // Minimum width needed: padding (16*2) + image (48) + spacing (12) + min text width (60) = 32 + 48 + 12 + 60 = 152
        // Adding safety margin to prevent edge cases
        final minWidth = 160.0;

        // If width is too small, hide episode info during animation
        if (constraints.maxWidth < minWidth) {
          return const SizedBox.shrink();
        }

        // Calculate available width for image
        final availableWidth = constraints.maxWidth - 32; // subtract padding
        final imageSize = availableWidth < 100 ? 32.0 : 48.0; // smaller image for tight spaces

        return InkWell(
          onTap: widget.onNavigateToEpisode,
          borderRadius: BorderRadius.circular(8),
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                // Podcast icon - flexible size
                Container(
                  width: imageSize,
                  height: imageSize,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(8),
                    child: _buildEpisodeImage(context),
                  ),
                ),
                const SizedBox(width: 12),
                // Title and info
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        widget.episode.title,
                        style: TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 4),
                      // Info row with flexible layout to prevent overflow
                      Row(
                        children: [
                          Icon(
                            Icons.calendar_today_outlined,
                            size: 12,
                            color: Theme.of(context).colorScheme.onSurfaceVariant,
                          ),
                          const SizedBox(width: 4),
                          Expanded(
                            child: Text(
                              _formatDate(widget.episode.publishedAt),
                              style: TextStyle(
                                fontSize: 12,
                                color: Theme.of(context).colorScheme.onSurfaceVariant,
                              ),
                              overflow: TextOverflow.ellipsis,
                              maxLines: 1,
                            ),
                          ),
                        ],
                      ),
                      // Duration on a separate line to prevent overflow
                      if (widget.episode.audioDuration != null)
                        Consumer(
                          builder: (context, ref, _) {
                            final audioPlayerState = ref.watch(audioPlayerProvider);
                            // Use audio player duration if available (more accurate), otherwise fall back to episode duration
                            final displayDuration = (audioPlayerState.currentEpisode?.id == widget.episode.id &&
                                audioPlayerState.duration > 0)
                                ? audioPlayerState.duration
                                : widget.episode.audioDuration!;

                            return Padding(
                              padding: const EdgeInsets.only(top: 2),
                              child: Row(
                                children: [
                                  Icon(
                                    Icons.schedule_outlined,
                                    size: 12,
                                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                                  ),
                                  const SizedBox(width: 4),
                                  Expanded(
                                    child: Text(
                                      _formatDuration(displayDuration),
                                      style: TextStyle(
                                        fontSize: 12,
                                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                                      ),
                                      overflow: TextOverflow.ellipsis,
                                      maxLines: 1,
                                    ),
                                  ),
                                ],
                              ),
                            );
                          },
                        ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildEpisodeImage(BuildContext context) {
    final imageUrl = widget.episode.subscriptionImageUrl ?? widget.episode.imageUrl;

    if (imageUrl != null && imageUrl.isNotEmpty) {
      return Image.network(
        imageUrl,
        fit: BoxFit.cover,
        errorBuilder: (context, error, stackTrace) {
          return _buildDefaultCover(context);
        },
      );
    }

    return _buildDefaultCover(context);
  }

  Widget _buildDefaultCover(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            Theme.of(context).colorScheme.primary,
            Theme.of(context).colorScheme.secondary,
          ],
        ),
      ),
      child: Center(
        child: Icon(
          Icons.podcasts,
          size: 24,
          color: Theme.of(context).colorScheme.onPrimary.withValues(alpha: 0.7),
        ),
      ),
    );
  }

  Widget _buildProgressBar(BuildContext context) {
    final progress = widget.duration > 0 ? widget.position / widget.duration : 0.0;

    return LayoutBuilder(
      builder: (context, constraints) {
        // Minimum width needed for progress bar: padding (16*2) + slider + time labels (80) = 32 + 80 = 112
        // Adding safety margin to prevent edge cases
        final minWidth = 120.0;

        // If width is too small, hide progress bar during animation
        if (constraints.maxWidth < minWidth) {
          return const SizedBox.shrink();
        }

        // Show time labels only if there's enough space
        final showTimeLabels = constraints.maxWidth >= 170.0;

        return Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Column(
            children: [
              SliderTheme(
                data: SliderTheme.of(context).copyWith(
                  trackHeight: 3,
                  thumbShape: const RoundSliderThumbShape(enabledThumbRadius: 6),
                  overlayShape: const RoundSliderOverlayShape(overlayRadius: 12),
                ),
                child: Slider(
                  value: progress.clamp(0.0, 1.0),
                  onChanged: (value) {
                    final newPosition = (value * widget.duration).round();
                    widget.onSeek(newPosition);
                  },
                  activeColor: Theme.of(context).colorScheme.primary,
                ),
              ),
              // Only show time labels if width allows
              if (showTimeLabels)
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 8),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        _formatDuration(widget.position),
                        style: TextStyle(
                          fontSize: 12,
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                      ),
                      Text(
                        _formatRemainingTime(),
                        style: TextStyle(
                          fontSize: 12,
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
            ],
          ),
        );
      },
    );
  }

  String _formatRemainingTime() {
    final remaining = widget.duration - widget.position;
    if (remaining <= 0) {
      return '-00:00';
    }

    final seconds = (remaining / 1000).floor();
    final hours = seconds ~/ 3600;
    final minutes = (seconds % 3600) ~/ 60;
    final secs = seconds % 60;

    if (hours > 0) {
      return "-${hours.toString().padLeft(1, '0')}:${minutes.toString().padLeft(2, '0')}:${secs.toString().padLeft(2, '0')}";
    }
    return '-${minutes.toString().padLeft(2, '0')}:${secs.toString().padLeft(2, '0')}';
  }

  Widget _buildPlaybackControls(BuildContext context) {
    final l10n = AppLocalizations.of(context);

    return LayoutBuilder(
      builder: (context, constraints) {
        // Minimum width needed: 3 buttons (~44px each) + spacing + margins = 150px minimum
        // Adding extra margin to prevent edge cases
        final minWidth = 150.0;

        // If width is too small, hide playback controls during animation
        if (constraints.maxWidth < minWidth) {
          return const SizedBox.shrink();
        }

        return Row(
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
          children: [
            // Rewind 10s
            _buildControlButton(
              context,
              icon: Icons.replay_10,
              label: '-10',
              tooltip: l10n?.podcast_player_rewind_10 ?? 'Rewind 10s',
              onTap: widget.onRewind,
            ),
            // Play/Pause
            Container(
              width: 56,
              height: 56,
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.primary,
                shape: BoxShape.circle,
                boxShadow: [
                  BoxShadow(
                    color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
                    blurRadius: 8,
                    offset: const Offset(0, 3),
                  ),
                ],
              ),
              child: IconButton(
                onPressed: widget.isLoading ? null : widget.onPlayPause,
                tooltip: widget.isPlaying
                    ? (l10n?.podcast_player_pause ?? 'Pause')
                    : (l10n?.podcast_player_play ?? 'Play'),
                icon: widget.isLoading
                    ? const SizedBox(
                        width: 24,
                        height: 24,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                        ),
                      )
                    : Icon(
                        widget.isPlaying ? Icons.pause : Icons.play_arrow,
                        color: Colors.white,
                        size: 32,
                      ),
              ),
            ),
            // Forward 30s
            _buildControlButton(
              context,
              icon: Icons.forward_30,
              label: '+30',
              tooltip: l10n?.podcast_player_forward_30 ?? 'Forward 30s',
              onTap: widget.onForward,
            ),
          ],
        );
      },
    );
  }

  Widget _buildControlButton(
    BuildContext context, {
    required IconData icon,
    required String label,
    String? tooltip,
    required VoidCallback onTap,
  }) {
    final child = Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(20),
        child: Container(
          padding: const EdgeInsets.all(8),
          child: Icon(
            icon,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
            size: 28,
          ),
        ),
      ),
    );

    if (tooltip != null) {
      return Tooltip(message: tooltip, child: child);
    }
    return child;
  }

  Widget _buildOptionsRow(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    if (l10n == null) {
      return const SizedBox.shrink();
    }

    return LayoutBuilder(
      builder: (context, constraints) {
        // Minimum width needed for full options row
        // Speed button (~70) + 3 icon buttons (~40 each) + spacing = ~200px
        final minWidthForFullRow = 200.0;
        final showFullOptions = constraints.maxWidth >= minWidthForFullRow;

        // If width is too small, hide the options row entirely during animation
        if (constraints.maxWidth < 150.0) {
          return const SizedBox.shrink();
        }

        return Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Wrap(
            alignment: WrapAlignment.center,
            spacing: 16,
            runSpacing: 12,
            children: [
              // Playback speed - always show if there's enough space
              if (showFullOptions) _buildSpeedButton(context),
              // Other buttons - hide if width is limited
              if (showFullOptions) ...[
                // Playlist button (placeholder)
                _buildIconButton(
                  context,
                  icon: Icons.list,
                  tooltip: l10n.podcast_player_list,
                  onTap: () {
                    // TODO: Implement playlist
                  },
                ),
                // Sleep timer (placeholder)
                _buildIconButton(
                  context,
                  icon: Icons.bedtime_outlined,
                  tooltip: l10n.podcast_player_sleep_mode,
                  onTap: () {
                    // TODO: Implement sleep timer
                  },
                ),
                // Download button (placeholder)
                _buildIconButton(
                  context,
                  icon: Icons.download_outlined,
                  tooltip: l10n.podcast_player_download,
                  onTap: () {
                    // TODO: Implement download
                  },
                ),
              ],
            ],
          ),
        );
      },
    );
  }

  Widget _buildSpeedButton(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;
    final isMobile = screenWidth < 600;

    // 桌面端使用下拉框，移动端使用滚筒选择器
    if (!isMobile) {
      return _buildDesktopSpeedDropdown(context);
    }

    return _buildMobileSpeedButton(context);
  }

  /// 桌面端倍速下拉框
  Widget _buildDesktopSpeedDropdown(BuildContext context) {
    // 可用的倍速选项
    final speedOptions = [0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0];

    return Container(
      constraints: const BoxConstraints(
        minWidth: 70, // 确保最小宽度
        maxWidth: 100, // 限制最大宽度
      ),
      decoration: BoxDecoration(
        border: Border.all(
          color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.5),
        ),
        borderRadius: BorderRadius.circular(16),
        color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
      ),
      // 使用与其他图标按钮一致的 padding
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
        child: DropdownButtonHideUnderline(
          child: DropdownButton<double>(
            value: widget.playbackRate,
            // 图标放在右侧
            icon: const Icon(Icons.expand_more, size: 16),
            iconSize: 16,
            elevation: 8,
            isDense: true, // 减少垂直空间
            isExpanded: true, // 让下拉框占满可用空间
            style: TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w600,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            itemHeight: 48, // 设置下拉项高度
            selectedItemBuilder: (BuildContext context) {
              return speedOptions.map<Widget>((double value) {
                return Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      Icons.speed,
                      size: 14,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                    const SizedBox(width: 4),
                    Flexible(
                      child: Text(
                        '${value.toStringAsFixed(2)}x'.replaceAll(RegExp(r'\.?0+$'), ''),
                        style: TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ],
                );
              }).toList();
            },
            onChanged: (double? newValue) {
              if (newValue != null) {
                widget.onSpeedChange(newValue);
              }
            },
            items: speedOptions.map<DropdownMenuItem<double>>((double value) {
              return DropdownMenuItem<double>(
                value: value,
                child: Text('${value.toStringAsFixed(2)}x'.replaceAll(RegExp(r'\.?0+$'), '')),
              );
            }).toList(),
          ),
        ),
      ),
    );
  }

  /// 移动端倍速按钮（点击弹出滚筒选择器）
  Widget _buildMobileSpeedButton(BuildContext context) {
    return Container(
      key: _speedButtonKey,
      decoration: BoxDecoration(
        border: Border.all(
          color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.5),
        ),
        borderRadius: BorderRadius.circular(16),
        color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: () async {
            // 显示滚筒样式倍速选择弹窗（从按钮位置向上展开）
            await SpeedPickerPopup.show(
              context: context,
              buttonKey: _speedButtonKey,
              initialValue: widget.playbackRate,
              onSpeedChanged: (speed) {
                // 实时更新播放速度
                widget.onSpeedChange(speed);
              },
            );
          },
          borderRadius: BorderRadius.circular(16),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  Icons.speed,
                  size: 14,
                  color: Theme.of(context).colorScheme.primary,
                ),
                const SizedBox(width: 4),
                Text(
                  '${(widget.playbackRate * 10).roundToDouble() / 10}x',
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildIconButton(
    BuildContext context, {
    required IconData icon,
    required String tooltip,
    required VoidCallback onTap,
  }) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(20),
        child: Container(
          padding: const EdgeInsets.all(8),
          child: Icon(
            icon,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
            size: 24,
          ),
        ),
      ),
    );
  }

  String _formatDate(DateTime date) {
    final localDate = date.isUtc ? date.toLocal() : date;
    final year = localDate.year;
    final month = localDate.month.toString().padLeft(2, '0');
    final day = localDate.day.toString().padLeft(2, '0');
    return '$year年$month月$day日';
  }

  String _formatDuration(int milliseconds) {
    final duration = Duration(milliseconds: milliseconds);
    final hours = duration.inHours;
    final minutes = duration.inMinutes.remainder(60);
    final seconds = duration.inSeconds.remainder(60);

    if (hours > 0) {
      return '${hours.toString().padLeft(2, '0')}:${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';
    }
    return '${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';
  }
}
