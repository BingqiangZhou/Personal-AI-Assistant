import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:dartz/dartz.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter/foundation.dart';

import '../../domain/models/auth_request.dart';
import '../../domain/models/user.dart';
import '../../domain/repositories/auth_repository.dart';
import '../../data/repositories/auth_repository_impl.dart';
import '../../data/datasources/auth_remote_datasource.dart';
import '../../../../core/network/exceptions/network_exceptions.dart';
import '../../../../core/storage/secure_storage_service.dart';
import '../../../../core/network/dio_client.dart';
import '../../../../core/providers/core_providers.dart';

// Storage provider
final secureStorageProvider = Provider<SecureStorageService>((ref) {
  return SecureStorageServiceImpl(const FlutterSecureStorage());
});

// Remote datasource provider - use shared DioClient
final authRemoteDatasourceProvider = Provider<AuthRemoteDatasource>((ref) {
  final dioClient = ref.watch(dioClientProvider);
  return AuthRemoteDatasourceImpl(dioClient);
});

// Repository provider
final authRepositoryProvider = Provider<AuthRepository>((ref) {
  final remoteDatasource = ref.watch(authRemoteDatasourceProvider);
  final secureStorage = ref.watch(secureStorageProvider);
  return AuthRepositoryImpl(remoteDatasource, secureStorage);
});

// Auth state notifier provider
final authProvider = NotifierProvider<AuthNotifier, AuthState>(AuthNotifier.new);

class AuthState {
  final User? user;
  final bool isLoading;
  final bool isAuthenticated;
  final String? error;
  final bool isRefreshingToken;
  final AuthOperation? currentOperation;
  final Map<String, String>? fieldErrors; // For validation errors

  const AuthState({
    this.user,
    this.isLoading = false,
    this.isAuthenticated = false,
    this.error,
    this.isRefreshingToken = false,
    this.currentOperation,
    this.fieldErrors,
  });

  AuthState copyWith({
    User? user,
    bool? isLoading,
    bool? isAuthenticated,
    String? error,
    bool? isRefreshingToken,
    AuthOperation? currentOperation,
    Map<String, String>? fieldErrors,
    bool clearError = false,
    bool clearFieldErrors = false,
  }) {
    return AuthState(
      user: user ?? this.user,
      isLoading: isLoading ?? this.isLoading,
      isAuthenticated: isAuthenticated ?? this.isAuthenticated,
      error: clearError ? null : (error ?? this.error),
      isRefreshingToken: isRefreshingToken ?? this.isRefreshingToken,
      currentOperation: currentOperation ?? this.currentOperation,
      fieldErrors: clearFieldErrors ? null : (fieldErrors ?? this.fieldErrors),
    );
  }
}

enum AuthOperation {
  login,
  register,
  logout,
  refreshToken,
  checkAuth,
  forgotPassword,
  resetPassword,
  verifyEmail,
}

class AuthNotifier extends Notifier<AuthState> {
  late final AuthRepository _authRepository;
  late final SecureStorageService _secureStorage;

  @override
  AuthState build() {
    _authRepository = ref.read(authRepositoryProvider);
    _secureStorage = ref.read(secureStorageProvider);
    // Don't check auth status here to avoid circular dependency
    // Let the UI call checkAuthStatus when needed
    return const AuthState();
  }

  Future<void> _checkAuthStatus() async {
    state = state.copyWith(isLoading: true, currentOperation: AuthOperation.checkAuth);

    try {
      final token = await _secureStorage.getAccessToken();
      if (token != null) {
        // Check if token is expired (if we have expiry info)
        final tokenExpiry = await _secureStorage.getTokenExpiry();
        if (tokenExpiry != null && DateTime.now().isAfter(tokenExpiry)) {
          // Token expired, try refresh
          final refreshSuccess = await _attemptTokenRefresh();
          if (!refreshSuccess) {
            await _clearAuthState();
            state = state.copyWith(
              isLoading: false,
              isAuthenticated: false,
              error: 'Session expired. Please login again.',
            );
            return;
          }
        }

        final result = await _authRepository.getCurrentUser();
        result.fold(
          (error) {
            String userMessage = _getErrorMessage(error);
            if (error is AuthenticationException) {
              _handleAuthError();
            }
            state = state.copyWith(
              isLoading: false,
              error: userMessage,
              currentOperation: null,
            );
          },
          (user) => state = state.copyWith(
            user: user,
            isAuthenticated: true,
            isLoading: false,
            error: null,
            currentOperation: null,
          ),
        );
      } else {
        state = state.copyWith(isLoading: false, currentOperation: null);
      }
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: 'Authentication check failed: ${e.toString()}',
        currentOperation: null,
      );
    }
  }

  Future<void> login({
    required String email, // Can be email or username
    required String password,
    bool rememberMe = false,
  }) async {
    state = state.copyWith(
      isLoading: true,
      error: null,
      clearFieldErrors: true,
      currentOperation: AuthOperation.login,
    );

    final request = LoginRequest(
      username: email, // Backend expects username field
      password: password,
      rememberMe: rememberMe,
    );

    final result = await _authRepository.login(request);
    result.fold(
      (error) {
        String userMessage = _getErrorMessage(error);
        Map<String, String>? fieldErrors = _getFieldErrors(error);

        state = state.copyWith(
          isLoading: false,
          error: userMessage,
          fieldErrors: fieldErrors,
          currentOperation: null,
        );
      },
      (authResponse) async {
        // Save token expiry if available
        if (authResponse.expiresIn > 0) {
          final expiryTime = DateTime.now().add(Duration(seconds: authResponse.expiresIn));
          _secureStorage.saveTokenExpiry(expiryTime);
        }

        // Fetch user info after successful login
        final userResult = await _authRepository.getCurrentUser();
        userResult.fold(
          (error) {
            // Even if user fetch fails, login was successful
            state = state.copyWith(
              isAuthenticated: true,
              isLoading: false,
              error: null,
              currentOperation: null,
            );
          },
          (user) {
            state = state.copyWith(
              user: user,
              isAuthenticated: true,
              isLoading: false,
              error: null,
              currentOperation: null,
            );
          },
        );
      },
    );
  }

  Future<void> register({
    required String email,
    required String password,
    String? username,
    bool rememberMe = false,
  }) async {
    state = state.copyWith(
      isLoading: true,
      error: null,
      clearFieldErrors: true,
      currentOperation: AuthOperation.register,
    );

    final request = RegisterRequest(
      email: email,
      password: password,
      username: username,
      rememberMe: rememberMe,
    );

    final result = await _authRepository.register(request);
    result.fold(
      (error) {
        // Debug logging
        debugPrint('=== Register Error Debug ===');
        debugPrint('Error type: ${error.runtimeType}');
        debugPrint('Error message: ${error.message}');
        debugPrint('Error statusCode: ${error.statusCode}');

        if (error is ValidationException) {
          debugPrint('Field errors: ${error.fieldErrors}');
          debugPrint('Error details: ${error.details}');
        }

        String userMessage = _getErrorMessage(error);
        Map<String, String>? fieldErrors = _getFieldErrors(error);

        debugPrint('User message: $userMessage');
        debugPrint('Field errors: $fieldErrors');
        debugPrint('========================');

        state = state.copyWith(
          isLoading: false,
          error: userMessage,
          fieldErrors: fieldErrors,
          currentOperation: null,
        );
      },
      (authResponse) async {
        // Save token expiry if available
        if (authResponse.expiresIn > 0) {
          final expiryTime = DateTime.now().add(Duration(seconds: authResponse.expiresIn));
          _secureStorage.saveTokenExpiry(expiryTime);
        }

        // Fetch user info after successful registration
        final userResult = await _authRepository.getCurrentUser();
        userResult.fold(
          (error) {
            // Even if user fetch fails, registration was successful
            state = state.copyWith(
              isAuthenticated: true,
              isLoading: false,
              error: null,
              currentOperation: null,
            );
          },
          (user) {
            state = state.copyWith(
              user: user,
              isAuthenticated: true,
              isLoading: false,
              error: null,
              currentOperation: null,
            );
          },
        );
      },
    );
  }

  Future<void> logout() async {
    state = state.copyWith(
      isLoading: true,
      currentOperation: AuthOperation.logout,
    );

    final refreshToken = await _secureStorage.getRefreshToken();
    final result = await _authRepository.logout(refreshToken);
    result.fold(
      (error) {
        // Even if logout API fails, clear local state
        _clearAuthState();
        state = state.copyWith(
          isLoading: false,
          currentOperation: null,
        );
      },
      (_) {
        _clearAuthState();
        state = const AuthState(
          isAuthenticated: false,
          isLoading: false,
        );
      },
    );
  }

  Future<void> refreshToken() async {
    if (state.isRefreshingToken) return;

    state = state.copyWith(
      isRefreshingToken: true,
      currentOperation: AuthOperation.refreshToken,
    );

    final refreshToken = await _secureStorage.getRefreshToken();
    if (refreshToken == null) {
      await _handleAuthError();
      state = state.copyWith(
        isRefreshingToken: false,
        currentOperation: null,
      );
      return;
    }

    final result = await _authRepository.refreshToken(refreshToken);
    result.fold(
      (error) async {
        await _handleAuthError();
        state = state.copyWith(
          isRefreshingToken: false,
          error: 'Session expired. Please login again.',
          currentOperation: null,
        );
      },
      (response) {
        // Update token expiry if available
        if (response.expiresIn > 0) {
          final expiryTime = DateTime.now().add(Duration(seconds: response.expiresIn));
          _secureStorage.saveTokenExpiry(expiryTime);
        }

        state = state.copyWith(
          isRefreshingToken: false,
          error: null,
          currentOperation: null,
        );
      },
    );
  }

  // Helper methods
  String _getErrorMessage(AppException error) {
    debugPrint('=== _getErrorMessage Debug ===');
    debugPrint('Error runtimeType: ${error.runtimeType}');
    debugPrint('Error message: ${error.message}');
    debugPrint('Error type check: ${error is ConflictException}');
    debugPrint('ConflictException type: ${ConflictException}');

    String result;
    switch (error.runtimeType) {
      case NetworkException:
        result = 'Network error. Please check your connection and try again.';
        break;
      case AuthenticationException:
        result = 'Invalid credentials. Please check your email and password.';
        break;
      case ValidationException:
        final validationError = error as ValidationException;
        result = validationError.message;
        debugPrint('ValidationException message: $result');
        break;
      case ServerException:
        result = 'Server error. Please try again later.';
        break;
      case AuthorizationException:
        result = 'You do not have permission to perform this action.';
        break;
      case NotFoundException:
        result = 'The requested resource was not found.';
        break;
      case ConflictException:
        result = error.message;
        debugPrint('ConflictException message: $result');
        break;
      default:
        result = 'An unexpected error occurred. Please try again.';
        debugPrint('Default error case triggered');
    }

    debugPrint('Result message: $result');
    debugPrint('==========================');
    return result;
  }

  Map<String, String>? _getFieldErrors(AppException error) {
    if (error is ValidationException) {
      debugPrint('=== _getFieldErrors Debug ===');
      debugPrint('error.fieldErrors: ${error.fieldErrors}');
      debugPrint('error.details: ${error.details}');
      debugPrint('=============================');

      // Try fieldErrors first (from our updated code)
      if (error.fieldErrors != null && error.fieldErrors!.isNotEmpty) {
        return Map<String, String>.from(error.fieldErrors!);
      }

      // Fall back to details (for backward compatibility)
      if (error.details != null && error.details!.isNotEmpty) {
        return Map<String, String>.from(error.details!);
      }
    }
    return null;
  }

  Future<void> _handleAuthError() async {
    await _clearAuthState();
    state = state.copyWith(
      isAuthenticated: false,
      user: null,
    );
  }

  Future<void> _clearAuthState() async {
    await _secureStorage.clearTokens();
    await _secureStorage.clearTokenExpiry();
  }

  Future<bool> _attemptTokenRefresh() async {
    final refreshToken = await _secureStorage.getRefreshToken();
    if (refreshToken == null) return false;

    final result = await _authRepository.refreshToken(refreshToken);
    return result.fold(
      (error) => false,
      (response) {
        if (response.expiresIn > 0) {
          final expiryTime = DateTime.now().add(Duration(seconds: response.expiresIn));
          _secureStorage.saveTokenExpiry(expiryTime);
        }
        return true;
      },
    );
  }

  void clearError() {
    state = state.copyWith(clearError: true);
  }

  void clearFieldErrors() {
    state = state.copyWith(clearFieldErrors: true);
  }

  Future<void> checkAuthStatus() async {
    await _checkAuthStatus();
  }

  Future<void> forgotPassword(String email) async {
    state = state.copyWith(
      isLoading: true,
      error: null,
      clearFieldErrors: true,
      currentOperation: AuthOperation.forgotPassword,
    );

    final request = ForgotPasswordRequest(email: email);

    final result = await _authRepository.forgotPassword(request);
    result.fold(
      (error) {
        String userMessage = _getErrorMessage(error);
        state = state.copyWith(
          isLoading: false,
          error: userMessage,
          currentOperation: null,
        );
      },
      (_) {
        state = state.copyWith(
          isLoading: false,
          error: null,
          currentOperation: null,
        );
      },
    );
  }

  Future<void> resetPassword({
    required String token,
    required String newPassword,
  }) async {
    state = state.copyWith(
      isLoading: true,
      error: null,
      clearFieldErrors: true,
      currentOperation: AuthOperation.resetPassword,
    );

    final request = ResetPasswordRequest(
      token: token,
      newPassword: newPassword,
    );

    final result = await _authRepository.resetPassword(request);
    result.fold(
      (error) {
        String userMessage = _getErrorMessage(error);
        Map<String, String>? fieldErrors = _getFieldErrors(error);

        state = state.copyWith(
          isLoading: false,
          error: userMessage,
          fieldErrors: fieldErrors,
          currentOperation: null,
        );
      },
      (_) {
        state = state.copyWith(
          isLoading: false,
          error: null,
          currentOperation: null,
        );
      },
    );
  }
}