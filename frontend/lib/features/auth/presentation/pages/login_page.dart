import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/app/config/app_config.dart';
import '../../../../core/localization/app_localizations.dart';
import '../../../../core/theme/app_theme.dart';
import '../../../../core/storage/local_storage_service.dart';
import '../../../../shared/widgets/loading_widget.dart';
import '../../../../shared/widgets/custom_text_field.dart';
import '../../../../shared/widgets/custom_button.dart';
import '../providers/auth_provider.dart';

class LoginPage extends ConsumerStatefulWidget {
  const LoginPage({super.key});

  @override
  ConsumerState<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends ConsumerState<LoginPage> {
  final _formKey = GlobalKey<FormState>();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  final _secureStorage = const FlutterSecureStorage();
  bool _obscurePassword = true;
  bool _rememberMe = false;

  @override
  void initState() {
    super.initState();
    _loadSavedCredentials();
  }

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  Future<void> _loadSavedCredentials() async {
    final savedUsername = await _secureStorage.read(key: AppConstants.savedUsernameKey);
    final savedPassword = await _secureStorage.read(key: AppConstants.savedPasswordKey);

    if (savedUsername != null && savedPassword != null) {
      setState(() {
        _emailController.text = savedUsername;
        _passwordController.text = savedPassword;
        _rememberMe = true;
      });
    }
  }

  Future<void> _login() async {
    if (_formKey.currentState!.validate()) {
      if (_rememberMe) {
        await _secureStorage.write(key: AppConstants.savedUsernameKey, value: _emailController.text.trim());
        await _secureStorage.write(key: AppConstants.savedPasswordKey, value: _passwordController.text);
      } else {
        await _secureStorage.delete(key: AppConstants.savedUsernameKey);
        await _secureStorage.delete(key: AppConstants.savedPasswordKey);
      }

      ref.read(authProvider.notifier).login(
        email: _emailController.text.trim(),
        password: _passwordController.text,
        rememberMe: _rememberMe,
      );
    }
  }

  Future<void> _showServerConfigDialog() async {
    final l10n = AppLocalizations.of(context)!;
    final storageService = ref.read(localStorageServiceProvider);
    final currentUrl = await storageService.getApiBaseUrl() ?? AppConfig.apiBaseUrl;
    final urlController = TextEditingController(text: currentUrl);

    if (!mounted) return;

    await showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.server_config_title),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(l10n.server_config_description),
            const SizedBox(height: 8),
            TextField(
              controller: urlController,
              decoration: InputDecoration(
                hintText: l10n.server_config_hint,
                border: const OutlineInputBorder(),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(l10n.cancel),
          ),
          TextButton(
            onPressed: () async {
              final newUrl = urlController.text.trim();
              if (newUrl.isNotEmpty) {
                // Capture context before async operation
                final ctx = context;
                await storageService.saveApiBaseUrl(newUrl);
                AppConfig.setApiBaseUrl(newUrl);

                if (mounted) {
                  Navigator.pop(ctx);
                  ScaffoldMessenger.of(ctx).showSnackBar(
                    SnackBar(content: Text(l10n.server_config_saved)),
                  );
                }
              }
            },
            child: Text(l10n.save),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final authState = ref.watch(authProvider);
    final isLoading = authState.isLoading;

    // Listen for auth state changes
    ref.listen<AuthState>(authProvider, (previous, next) {
      // Only navigate if user just became authenticated
      final wasAuthenticated = previous?.isAuthenticated ?? false;
      final isAuthenticated = next.isAuthenticated;

      if (isAuthenticated && !wasAuthenticated) {
        context.go('/home');
      } else if (next.error != null && next.error != previous?.error) {
        // Only show snackbar for new errors
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(next.error!),
              backgroundColor: AppTheme.errorColor,
            ),
          );
        }
      }
    });

    return Scaffold(
      body: SafeArea(
        child: LoadingOverlay(
          isLoading: isLoading,
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24.0),
            child: Form(
              key: _formKey,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const SizedBox(height: 60),

                  // Logo and title
                  Center(
                    child: Column(
                      children: [
                        Material(
                          color: Colors.transparent,
                          child: InkWell(
                            onLongPress: _showServerConfigDialog,
                            borderRadius: BorderRadius.circular(20),
                            child: Image.asset(
                              'assets/icons/appLogo.png',
                              width: 80,
                              height: 80,
                            ),
                          ),
                        ),
                        const SizedBox(height: 16),
                        Text(
                          l10n.auth_welcome_back,
                          style: Theme.of(context).textTheme.headlineLarge?.copyWith(
                            fontWeight: FontWeight.bold,
                            color: Theme.of(context).colorScheme.primary,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          l10n.auth_sign_in_subtitle,
                          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                            color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.7),
                          ),
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 48),

                  // Email field
                  CustomTextField(
                    controller: _emailController,
                    label: l10n.auth_email,
                    keyboardType: TextInputType.emailAddress,
                    prefixIcon: const Icon(Icons.email_outlined),
                    validator: (value) {
                      if (value == null || value.isEmpty) {
                        return l10n.auth_enter_email;
                      }
                      if (!value.contains('@')) {
                        return l10n.auth_enter_valid_email;
                      }
                      return null;
                    },
                  ),

                  const SizedBox(height: 16),

                  // Password field
                  CustomTextField(
                    controller: _passwordController,
                    label: l10n.auth_password,
                    obscureText: _obscurePassword,
                    prefixIcon: const Icon(Icons.lock_outline),
                    suffixIcon: IconButton(
                      icon: Icon(
                        _obscurePassword ? Icons.visibility_off : Icons.visibility,
                      ),
                      onPressed: () {
                        setState(() {
                          _obscurePassword = !_obscurePassword;
                        });
                      },
                    ),
                    validator: (value) {
                      if (value == null || value.isEmpty) {
                        return l10n.auth_enter_password;
                      }
                      if (value.length < 6) {
                        return l10n.auth_password_too_short;
                      }
                      return null;
                    },
                  ),

                  const SizedBox(height: 16),

                  // Remember me and Forgot password
                  Row(
                    children: [
                      Checkbox(
                        value: _rememberMe,
                        onChanged: (value) async {
                          setState(() {
                            _rememberMe = value ?? false;
                          });
                          if (!_rememberMe) {
                            await _secureStorage.delete(key: AppConstants.savedUsernameKey);
                            await _secureStorage.delete(key: AppConstants.savedPasswordKey);
                          }
                        },
                      ),
                      Text(l10n.auth_remember_me),
                      const Spacer(),
                      TextButton(
                        onPressed: () {
                          context.go('/forgot-password');
                        },
                        child: Text(
                          l10n.auth_forgot_password,
                          style: TextStyle(
                            color: Theme.of(context).colorScheme.primary,
                          ),
                        ),
                      ),
                    ],
                  ),

                  const SizedBox(height: 32),

                  // Login button
                  CustomButton(
                    key: const Key('login_button'),
                    text: l10n.auth_login,
                    onPressed: _login,
                    isLoading: isLoading,
                  ),

                  const SizedBox(height: 32),

                  // Sign up link
                  Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Text(
                        l10n.auth_no_account,
                        style: Theme.of(context).textTheme.bodyMedium,
                      ),
                      GestureDetector(
                        onTap: () => context.go('/register'),
                        child: Text(
                          l10n.auth_sign_up,
                          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                            color: Theme.of(context).colorScheme.primary,
                            fontWeight: FontWeight.w600,
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
    );
  }
}