import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../providers/podcast_providers.dart';

class AddPodcastDialog extends ConsumerStatefulWidget {
  const AddPodcastDialog({super.key});

  @override
  ConsumerState<AddPodcastDialog> createState() => _AddPodcastDialogState();
}

class _AddPodcastDialogState extends ConsumerState<AddPodcastDialog> {
  final _formKey = GlobalKey<FormState>();
  final _feedUrlController = TextEditingController();
  final _customNameController = TextEditingController();
  bool _isLoading = false;

  @override
  void dispose() {
    _feedUrlController.dispose();
    _customNameController.dispose();
    super.dispose();
  }

  Future<void> _addSubscription() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() {
      _isLoading = true;
    });

    try {
      await ref.read(podcastSubscriptionProvider.notifier).addSubscription(
            feedUrl: _feedUrlController.text.trim(),
            customName: _customNameController.text.trim().isNotEmpty
                ? _customNameController.text.trim()
                : null,
          );

      if (mounted) {
        Navigator.of(context).pop();
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Podcast added successfully!'),
            backgroundColor: Colors.green,
          ),
        );
      }
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to add podcast: $error'),
            backgroundColor: Colors.red,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _isLoading = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      child: Container(
        constraints: const BoxConstraints(maxWidth: 500),
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Add Podcast',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 24),
            Form(
              key: _formKey,
              child: Column(
                children: [
                  TextFormField(
                    controller: _feedUrlController,
                    decoration: const InputDecoration(
                      labelText: 'RSS Feed URL',
                      hintText: 'https://example.com/podcast/feed.xml',
                      border: OutlineInputBorder(),
                      prefixIcon: Icon(Icons.rss_feed),
                    ),
                    validator: (value) {
                      if (value == null || value.trim().isEmpty) {
                        return 'Please enter a RSS feed URL';
                      }
                      if (!value.startsWith('http://') && !value.startsWith('https://')) {
                        return 'Please enter a valid URL starting with http:// or https://';
                      }
                      return null;
                    },
                  ),
                  const SizedBox(height: 16),
                  TextFormField(
                    controller: _customNameController,
                    decoration: const InputDecoration(
                      labelText: 'Custom Name (Optional)',
                      hintText: 'My Podcast',
                      border: OutlineInputBorder(),
                      prefixIcon: Icon(Icons.edit),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 24),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                TextButton(
                  onPressed: _isLoading ? null : () => Navigator.of(context).pop(),
                  child: const Text('Cancel'),
                ),
                const SizedBox(width: 16),
                ElevatedButton.icon(
                  onPressed: _isLoading ? null : _addSubscription,
                  icon: _isLoading
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.add),
                  label: Text(_isLoading ? 'Adding...' : 'Add Podcast'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}