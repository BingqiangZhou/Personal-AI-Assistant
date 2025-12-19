import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../data/models/podcast_subscription_model.dart';
import '../providers/podcast_providers.dart';
import '../widgets/add_podcast_dialog.dart';
import '../widgets/podcast_subscription_card.dart';

class PodcastListPage extends ConsumerStatefulWidget {
  const PodcastListPage({super.key});

  @override
  ConsumerState<PodcastListPage> createState() => _PodcastListPageState();
}

class _PodcastListPageState extends ConsumerState<PodcastListPage> {
  final ScrollController _scrollController = ScrollController();
  String _searchQuery = '';
  String _selectedStatus = 'all';

  @override
  void initState() {
    super.initState();
    // Load initial subscriptions
    Future.microtask(() {
      ref.read(podcastSubscriptionProvider.notifier).loadSubscriptions();
    });
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  Future<void> _refreshSubscriptions() async {
    await ref.read(podcastSubscriptionProvider.notifier).loadSubscriptions();
  }

  void _showAddPodcastDialog() {
    showDialog(
      context: context,
      builder: (context) => const AddPodcastDialog(),
    );
  }

  @override
  Widget build(BuildContext context) {
    final subscriptionsAsync = ref.watch(podcastSubscriptionProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Podcasts'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        actions: [
          IconButton(
            icon: const Icon(Icons.search),
            onPressed: _showSearchDialog,
          ),
          IconButton(
            icon: const Icon(Icons.filter_list),
            onPressed: _showFilterDialog,
          ),
          PopupMenuButton<String>(
            onSelected: (value) {
              switch (value) {
                case 'refresh_all':
                  _refreshSubscriptions();
                  break;
                case 'stats':
                  context.go('/podcasts/stats');
                  break;
              }
            },
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: 'refresh_all',
                child: Row(
                  children: [
                    Icon(Icons.refresh),
                    SizedBox(width: 8),
                    Text('Refresh All'),
                  ],
                ),
              ),
              const PopupMenuItem(
                value: 'stats',
                child: Row(
                  children: [
                    Icon(Icons.bar_chart),
                    SizedBox(width: 8),
                    Text('Statistics'),
                  ],
                ),
              ),
            ],
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: _refreshSubscriptions,
        child: subscriptionsAsync.when(
          data: (response) {
            if (response.subscriptions.isEmpty) {
              return _buildEmptyState();
            }
            return _buildSubscriptionList(response.subscriptions);
          },
          loading: () => const Center(
            child: CircularProgressIndicator(),
          ),
          error: (error, stack) => _buildErrorState(error),
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _showAddPodcastDialog,
        child: const Icon(Icons.add),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.podcasts_outlined,
            size: 80,
            color: Colors.grey[400],
          ),
          const SizedBox(height: 16),
          Text(
            'No Podcasts Yet',
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
              color: Colors.grey[600],
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Add your first podcast to get started',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
              color: Colors.grey[500],
            ),
          ),
          const SizedBox(height: 32),
          ElevatedButton.icon(
            onPressed: _showAddPodcastDialog,
            icon: const Icon(Icons.add),
            label: const Text('Add Podcast'),
          ),
        ],
      ),
    );
  }

  Widget _buildSubscriptionList(List<PodcastSubscriptionModel> subscriptions) {
    return ListView.builder(
      controller: _scrollController,
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: subscriptions.length,
      itemBuilder: (context, index) {
        final subscription = subscriptions[index];
        return PodcastSubscriptionCard(
          subscription: subscription,
          onRefresh: () async {
            try {
              await ref
                  .read(podcastSubscriptionProvider.notifier)
                  .refreshSubscription(subscription.id);
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('Podcast refreshed successfully!'),
                  backgroundColor: Colors.green,
                ),
              );
            } catch (error) {
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('Failed to refresh podcast: $error'),
                  backgroundColor: Colors.red,
                ),
              );
            }
          },
          onDelete: () async {
            try {
              await ref
                  .read(podcastSubscriptionProvider.notifier)
                  .deleteSubscription(subscription.id);
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('Podcast deleted successfully!'),
                  backgroundColor: Colors.green,
                ),
              );
            } catch (error) {
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('Failed to delete podcast: $error'),
                  backgroundColor: Colors.red,
                ),
              );
            }
          },
        );
      },
    );
  }

  Widget _buildErrorState(Object error) {
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
            'Failed to Load Podcasts',
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
            onPressed: _refreshSubscriptions,
            icon: const Icon(Icons.refresh),
            label: const Text('Retry'),
          ),
        ],
      ),
    );
  }

  void _showSearchDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Search Podcasts'),
        content: TextField(
          autofocus: true,
          decoration: const InputDecoration(
            labelText: 'Search term',
            hintText: 'Enter keywords to search...',
            border: OutlineInputBorder(),
          ),
          onChanged: (value) {
            setState(() {
              _searchQuery = value;
            });
          },
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () {
              Navigator.of(context).pop();
              if (_searchQuery.isNotEmpty) {
                context.go('/podcasts/search?q=$_searchQuery');
              }
            },
            child: const Text('Search'),
          ),
        ],
      ),
    );
  }

  void _showFilterDialog() {
    showDialog(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: const Text('Filter Podcasts'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('Status:'),
              const SizedBox(height: 8),
              RadioListTile<String>(
                title: const Text('All'),
                value: 'all',
                groupValue: _selectedStatus,
                onChanged: (value) {
                  setDialogState(() {
                    _selectedStatus = value!;
                  });
                },
              ),
              RadioListTile<String>(
                title: const Text('Active'),
                value: 'active',
                groupValue: _selectedStatus,
                onChanged: (value) {
                  setDialogState(() {
                    _selectedStatus = value!;
                  });
                },
              ),
              RadioListTile<String>(
                title: const Text('Error'),
                value: 'error',
                groupValue: _selectedStatus,
                onChanged: (value) {
                  setDialogState(() {
                    _selectedStatus = value!;
                  });
                },
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Cancel'),
            ),
            TextButton(
              onPressed: () {
                Navigator.of(context).pop();
                setState(() {
                  // Apply filter
                  ref
                      .read(podcastSubscriptionProvider.notifier)
                      .loadSubscriptions(
                        status: _selectedStatus == 'all' ? null : _selectedStatus,
                      );
                });
              },
              child: const Text('Apply'),
            ),
          ],
        ),
      ),
    );
  }
}