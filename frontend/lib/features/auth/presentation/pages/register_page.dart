import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/theme/app_theme.dart';
import '../../../../shared/widgets/loading_widget.dart';
import '../../../../shared/widgets/custom_text_field.dart';
import '../../../../shared/widgets/custom_button.dart';
import '../providers/auth_provider.dart';
import '../widgets/password_requirement_item.dart';

class RegisterPage extends ConsumerStatefulWidget {
  const RegisterPage({super.key});

  @override
  ConsumerState<RegisterPage> createState() => _RegisterPageState();
}

class _RegisterPageState extends ConsumerState<RegisterPage> {
  final _formKey = GlobalKey<FormState>();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  final _confirmPasswordController = TextEditingController();
  final _usernameController = TextEditingController();
  bool _obscurePassword = true;
  bool _obscureConfirmPassword = true;
  bool _agreeToTerms = false;

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    _usernameController.dispose();
    super.dispose();
  }

  void _clearFieldErrors() {
    ref.read(authProvider.notifier).clearFieldErrors();
  }

  void _register() {
    if (_formKey.currentState!.validate() && _agreeToTerms) {
      ref.read(authProvider.notifier).register(
        email: _emailController.text.trim(),
        password: _passwordController.text,
        username: _usernameController.text.trim().isEmpty
            ? null
            : _usernameController.text.trim(),
      );
    } else if (!_agreeToTerms) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Please agree to the terms and conditions'),
          backgroundColor: AppTheme.warningColor,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final authState = ref.watch(authProvider);
    final isLoading = authState.isLoading;

    ref.listen<AuthState>(authProvider, (previous, next) {
      if (next.user != null) {
        context.go('/home');
      } else if (next.error != null && next.fieldErrors == null) {
        // Only show snackbar if there are no field errors
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(next.error!),
            backgroundColor: AppTheme.errorColor,
          ),
        );
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
                  const SizedBox(height: 40),

                  // Logo and title
                  Center(
                    child: Column(
                      children: [
                        Container(
                          width: 80,
                          height: 80,
                          decoration: BoxDecoration(
                            color: AppTheme.primaryColor,
                            borderRadius: BorderRadius.circular(20),
                          ),
                          child: const Icon(
                            Icons.person_add,
                            size: 40,
                            color: Colors.white,
                          ),
                        ),
                        const SizedBox(height: 16),
                        Text(
                          'Create Account',
                          style: Theme.of(context).textTheme.headlineLarge?.copyWith(
                            fontWeight: FontWeight.bold,
                            color: Theme.of(context).colorScheme.primary,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          'Join us to start your AI journey',
                          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                            color: Theme.of(context).colorScheme.onBackground.withOpacity(0.7),
                          ),
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 32),

                  // Username field
                  CustomTextField(
                    controller: _usernameController,
                    label: '用户名 (可选)',
                    prefixIcon: const Icon(Icons.person_outline),
                    onChanged: (value) {
                      _clearFieldErrors();
                      setState(() {}); // Trigger rebuild to update password requirements
                    },
                    validator: (value) {
                      // Username is optional
                      return null;
                    },
                  ),

                  const SizedBox(height: 16),

                  // Email field
                  CustomTextField(
                    controller: _emailController,
                    label: 'Email',
                    keyboardType: TextInputType.emailAddress,
                    prefixIcon: const Icon(Icons.email_outlined),
                    onChanged: (value) {
                      _clearFieldErrors();
                      setState(() {}); // Trigger rebuild to update password requirements
                    },
                    validator: (value) {
                      if (value == null || value.isEmpty) {
                        return 'Please enter your email';
                      }
                      if (!value.contains('@')) {
                        return 'Please enter a valid email';
                      }
                      return null;
                    },
                    errorText: authState.fieldErrors?['email'],
                  ),

                  const SizedBox(height: 16),

                  // Password field
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      CustomTextField(
                        controller: _passwordController,
                        label: 'Password',
                        obscureText: _obscurePassword,
                        prefixIcon: const Icon(Icons.lock_outline),
                        suffixIcon: IconButton(
                          key: const Key('password_visibility_toggle'),
                          icon: Icon(
                            _obscurePassword ? Icons.visibility_off : Icons.visibility,
                          ),
                          onPressed: () {
                            setState(() {
                              _obscurePassword = !_obscurePassword;
                            });
                          },
                        ),
                        onChanged: (value) => _clearFieldErrors(),
                        validator: (value) {
                          if (value == null || value.isEmpty) {
                            return 'Please enter your password';
                          }
                          if (value.length < 8) {
                            return 'Password must be at least 8 characters';
                          }
                          if (!value.contains(RegExp(r'[A-Z]'))) {
                            return 'Password must contain at least one uppercase letter (A-Z)';
                          }
                          if (!value.contains(RegExp(r'[a-z]'))) {
                            return 'Password must contain at least one lowercase letter (a-z)';
                          }
                          if (!value.contains(RegExp(r'[0-9]'))) {
                            return 'Password must contain at least one number (0-9)';
                          }
                          return null;
                        },
                        errorText: authState.fieldErrors?['password'],
                      ),
                      const SizedBox(height: 8),
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: Theme.of(context).colorScheme.surfaceVariant.withOpacity(0.5),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(
                            color: Theme.of(context).colorScheme.outline.withOpacity(0.3),
                          ),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Password Requirements:',
                              style: Theme.of(context).textTheme.labelMedium?.copyWith(
                                fontWeight: FontWeight.w600,
                                color: Theme.of(context).colorScheme.onSurfaceVariant,
                              ),
                            ),
                            const SizedBox(height: 8),
                            PasswordRequirementItem(
                              text: 'At least 8 characters',
                              isValid: _passwordController.text.length >= 8,
                            ),
                            PasswordRequirementItem(
                              text: 'One uppercase letter (A-Z)',
                              isValid: _passwordController.text.contains(RegExp(r'[A-Z]')),
                            ),
                            PasswordRequirementItem(
                              text: 'One lowercase letter (a-z)',
                              isValid: _passwordController.text.contains(RegExp(r'[a-z]')),
                            ),
                            PasswordRequirementItem(
                              text: 'One number (0-9)',
                              isValid: _passwordController.text.contains(RegExp(r'[0-9]')),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),

                  const SizedBox(height: 16),

                  // Confirm password field
                  CustomTextField(
                    controller: _confirmPasswordController,
                    label: 'Confirm Password',
                    obscureText: _obscureConfirmPassword,
                    prefixIcon: const Icon(Icons.lock_outline),
                    suffixIcon: IconButton(
                      icon: Icon(
                        _obscureConfirmPassword ? Icons.visibility_off : Icons.visibility,
                      ),
                      onPressed: () {
                        setState(() {
                          _obscureConfirmPassword = !_obscureConfirmPassword;
                        });
                      },
                    ),
                    validator: (value) {
                      if (value == null || value.isEmpty) {
                        return 'Please confirm your password';
                      }
                      if (value != _passwordController.text) {
                        return 'Passwords do not match';
                      }
                      return null;
                    },
                  ),

                  const SizedBox(height: 24),

                  // Terms and conditions
                  Row(
                    children: [
                      Checkbox(
                        value: _agreeToTerms,
                        onChanged: (value) {
                          setState(() {
                            _agreeToTerms = value ?? false;
                          });
                        },
                      ),
                      Expanded(
                        child: Text.rich(
                          TextSpan(
                            text: 'I agree to the ',
                            style: Theme.of(context).textTheme.bodyMedium,
                            children: [
                              WidgetSpan(
                                child: GestureDetector(
                                  onTap: () {
                                    // TODO: Show terms and conditions
                                  },
                                  child: Text(
                                    'Terms and Conditions',
                                    style: TextStyle(
                                      color: Theme.of(context).colorScheme.primary,
                                      decoration: TextDecoration.underline,
                                    ),
                                  ),
                                ),
                              ),
                              const TextSpan(text: ' and '),
                              WidgetSpan(
                                child: GestureDetector(
                                  onTap: () {
                                    // TODO: Show privacy policy
                                  },
                                  child: Text(
                                    'Privacy Policy',
                                    style: TextStyle(
                                      color: Theme.of(context).colorScheme.primary,
                                      decoration: TextDecoration.underline,
                                    ),
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ],
                  ),

                  const SizedBox(height: 32),

                  // Register button
                  CustomButton(
                    key: const Key('register_button'),
                    text: 'Create Account',
                    onPressed: _register,
                    isLoading: isLoading,
                  ),

                  const SizedBox(height: 32),

                  // Sign in link
                  Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Text(
                        'Already have an account? ',
                        style: Theme.of(context).textTheme.bodyMedium,
                      ),
                      GestureDetector(
                        onTap: () => context.go('/login'),
                        child: Text(
                          'Sign In',
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