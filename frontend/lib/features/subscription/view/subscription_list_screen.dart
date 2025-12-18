import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Desktop version of subscription list screen
class SubscriptionListScreen extends ConsumerStatefulWidget {
  const SubscriptionListScreen({super.key});

  @override
  ConsumerState<SubscriptionListScreen> createState() => _SubscriptionListScreenState();
}

class _SubscriptionListScreenState extends ConsumerState<SubscriptionListScreen> {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Subscriptions'),
      ),
      body: const Center(
        child: Text('Subscription management coming soon...'),
      ),
    );
  }
}
