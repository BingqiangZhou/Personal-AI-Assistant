import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../providers/auth_provider.dart';

class AuthTestPage extends ConsumerStatefulWidget {
  const AuthTestPage({super.key});

  @override
  ConsumerState<AuthTestPage> createState() => _AuthTestPageState();
}

class _AuthTestPageState extends ConsumerState<AuthTestPage> {
  final _loginFormKey = GlobalKey<FormState>();
  final _registerFormKey = GlobalKey<FormState>();

  final _loginEmailController = TextEditingController();
  final _loginPasswordController = TextEditingController();

  final _registerEmailController = TextEditingController();
  final _registerPasswordController = TextEditingController();
  final _registerUsernameController = TextEditingController();
  
  @override
  void dispose() {
    _loginEmailController.dispose();
    _loginPasswordController.dispose();
    _registerEmailController.dispose();
    _registerPasswordController.dispose();
    _registerUsernameController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final authState = ref.watch(authProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Authentication Test'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () {
              _loginEmailController.clear();
              _loginPasswordController.clear();
              _registerEmailController.clear();
              _registerPasswordController.clear();
              _registerUsernameController.clear();
              ref.read(authProvider.notifier).clearError();
              ref.read(authProvider.notifier).clearFieldErrors();
            },
            tooltip: 'Clear Forms',
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Current Auth State Display
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Authentication Status',
                      style: Theme.of(context).textTheme.headlineSmall,
                    ),
                    const SizedBox(height: 8),
                    if (authState.user != null) ...[
                      Text('ID: ${authState.user!.id}'),
                      Text('Email: ${authState.user!.email}'),
                      Text('Username: ${authState.user!.username ?? 'N/A'}'),
                      Text('Display Name: ${authState.user!.displayName}'),
                      Text('Verified: ${authState.user!.isVerified}'),
                    ] else
                      const Text('User: Not logged in'),
                    Text('Is Authenticated: ${authState.isAuthenticated}'),
                    Text('Is Loading: ${authState.isLoading}'),
                    Text('Is Refreshing Token: ${authState.isRefreshingToken}'),
                    if (authState.currentOperation != null)
                      Text('Current Operation: ${authState.currentOperation!.name}'),
                    if (authState.error != null) ...[
                      const SizedBox(height: 8),
                      Container(
                        padding: const EdgeInsets.all(8),
                        color: Colors.red.shade50,
                        child: Text(
                          'Error: ${authState.error}',
                          style: TextStyle(color: Colors.red.shade900),
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),

            const SizedBox(height: 20),

            // Login Form
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Form(
                  key: _loginFormKey,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Test Login',
                        style: Theme.of(context).textTheme.headlineSmall,
                      ),
                      const SizedBox(height: 12),
                      TextFormField(
                        controller: _loginEmailController,
                        decoration: const InputDecoration(
                          labelText: 'Email or Username',
                          border: OutlineInputBorder(),
                          hintText: 'Enter email or username',
                        ),
                        validator: (value) {
                          if (value == null || value.isEmpty) {
                            return 'Please enter email or username';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 12),
                      TextFormField(
                        controller: _loginPasswordController,
                        decoration: const InputDecoration(
                          labelText: 'Password',
                          border: OutlineInputBorder(),
                          hintText: 'Enter password',
                        ),
                        obscureText: true,
                        validator: (value) {
                          if (value == null || value.isEmpty) {
                            return 'Please enter password';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 12),
                      SizedBox(
                        width: double.infinity,
                        child: ElevatedButton(
                          onPressed: authState.isLoading
                              ? null
                              : () {
                                  if (_loginFormKey.currentState!.validate()) {
                                    ref.read(authProvider.notifier).login(
                                      email: _loginEmailController.text,
                                      password: _loginPasswordController.text,
                                    );
                                  }
                                },
                          child: authState.isLoading &&
                                  authState.currentOperation == AuthOperation.login
                              ? const SizedBox(
                                  height: 20,
                                  width: 20,
                                  child: CircularProgressIndicator(strokeWidth: 2),
                                )
                              : const Text('Login'),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),

            const SizedBox(height: 20),

            // Register Form
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Form(
                  key: _registerFormKey,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Test Register',
                        style: Theme.of(context).textTheme.headlineSmall,
                      ),
                      const SizedBox(height: 12),
                      TextFormField(
                        controller: _registerEmailController,
                        decoration: const InputDecoration(
                          labelText: 'Email',
                          border: OutlineInputBorder(),
                          hintText: 'Enter email',
                        ),
                        keyboardType: TextInputType.emailAddress,
                        validator: (value) {
                          if (value == null || value.isEmpty) {
                            return 'Please enter email';
                          }
                          if (!value.contains('@')) {
                            return 'Please enter a valid email';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 12),
                      const SizedBox(height: 12),
                      TextFormField(
                        controller: _registerPasswordController,
                        decoration: const InputDecoration(
                          labelText: 'Password',
                          border: OutlineInputBorder(),
                          hintText: 'Enter password (min 8 chars)',
                        ),
                        obscureText: true,
                        validator: (value) {
                          if (value == null || value.isEmpty) {
                            return 'Please enter password';
                          }
                          if (value.length < 8) {
                            return 'Password must be at least 8 characters';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 12),
                      SizedBox(
                        width: double.infinity,
                        child: ElevatedButton(
                          onPressed: authState.isLoading
                              ? null
                              : () {
                                  if (_registerFormKey.currentState!.validate()) {
                                    ref.read(authProvider.notifier).register(
                                      email: _registerEmailController.text,
                                      password: _registerPasswordController.text,
                                      username: _registerUsernameController.text.isEmpty
                                          ? null
                                          : _registerUsernameController.text,
                                    );
                                  }
                                },
                          child: authState.isLoading &&
                                  authState.currentOperation == AuthOperation.register
                              ? const SizedBox(
                                  height: 20,
                                  width: 20,
                                  child: CircularProgressIndicator(strokeWidth: 2),
                                )
                              : const Text('Register'),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),

            const SizedBox(height: 20),

            // Additional Actions
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text(
                      'Additional Actions',
                      style: Theme.of(context).textTheme.headlineSmall,
                    ),
                    const SizedBox(height: 12),
                    ElevatedButton.icon(
                      onPressed: authState.isAuthenticated &&
                              !authState.isRefreshingToken
                          ? () => ref.read(authProvider.notifier).logout()
                          : null,
                      icon: const Icon(Icons.logout),
                      label: const Text('Logout'),
                    ),
                    const SizedBox(height: 8),
                    ElevatedButton.icon(
                      onPressed: authState.isAuthenticated &&
                              !authState.isRefreshingToken
                          ? () => ref.read(authProvider.notifier).refreshToken()
                          : null,
                      icon: const Icon(Icons.refresh),
                      label: Text(authState.isRefreshingToken
                          ? 'Refreshing Token...'
                          : 'Refresh Token'),
                    ),
                  ],
                ),
              ),
            ),

            const SizedBox(height: 20),

            // Field Errors Display
            if (authState.fieldErrors != null) ...[
              Card(
                color: Colors.orange.shade50,
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Field Validation Errors',
                        style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                          color: Colors.orange.shade900,
                        ),
                      ),
                      const SizedBox(height: 8),
                      ...authState.fieldErrors!.entries.map(
                        (entry) => Padding(
                          padding: const EdgeInsets.symmetric(vertical: 2),
                          child: Row(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                '${entry.key}:',
                                style: TextStyle(
                                  fontWeight: FontWeight.bold,
                                  color: Colors.orange.shade900,
                                ),
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  entry.value,
                                  style: TextStyle(color: Colors.orange.shade800),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 20),
            ],

            // API Configuration Info
            Card(
              color: Colors.grey.shade100,
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'API Configuration',
                      style: Theme.of(context).textTheme.headlineSmall,
                    ),
                    const SizedBox(height: 8),
                    Text('Base URL: http://localhost:8000/api/v1'),
                    Text('Endpoints:'),
                    const SizedBox(height: 4),
                    const Text('  • POST /auth/login'),
                    const Text('  • POST /auth/register'),
                    const Text('  • POST /auth/refresh'),
                    const Text('  • POST /auth/logout'),
                    const Text('  • GET /auth/me'),
                    const SizedBox(height: 8),
                    const Text(
                      'Note: Make sure the backend server is running on localhost:8000',
                      style: TextStyle(
                        fontStyle: FontStyle.italic,
                        color: Colors.grey,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}