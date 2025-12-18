import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:go_router/go_router.dart';
import 'package:meta/meta.dart';

import '../../../core/constants/app_constants.dart';
import '../../../core/providers/core_providers.dart';
import '../models/auth_response.dart';
import '../models/user_model.dart';

// Authentication State
@immutable
class AuthState {
  final bool isLoading;
  final bool isAuthenticated;
  final UserModel? user;
  final String? error;

  const AuthState({
    this.isLoading = false,
    this.isAuthenticated = false,
    this.user,
    this.error,
  });

  AuthState copyWith({
    bool? isLoading,
    bool? isAuthenticated,
    UserModel? user,
    String? error,
  }) {
    return AuthState(
      isLoading: isLoading ?? this.isLoading,
      isAuthenticated: isAuthenticated ?? this.isAuthenticated,
      user: user ?? this.user,
      error: error ?? this.error,
    );
  }
}

// Authentication Provider
final authProvider = NotifierProvider<AuthNotifier, AuthState>(() {
  return AuthNotifier();
});

class AuthNotifier extends Notifier<AuthState> {
  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage();

  @override
  AuthState build() {
    _initializeAuth();
    return const AuthState();
  }

  // Initialize authentication state on app startup
  Future<void> _initializeAuth() async {
    try {
      state = state.copyWith(isLoading: true);

      // Check for stored token
      final token = await _secureStorage.read(key: AppConstants.tokenKey);

      if (token != null) {
        // Get current user
        final apiService = _ref.read(apiServiceProvider);
        final user = await apiService.getCurrentUser();

        state = state.copyWith(
          isAuthenticated: true,
          user: user,
          isLoading: false,
        );
      } else {
        state = state.copyWith(isLoading: false);
      }
    } catch (e) {
      // If token is invalid or other error, clear auth state
      await _clearAuthState();
      state = state.copyWith(
        isAuthenticated: false,
        user: null,
        isLoading: false,
        error: e.toString(),
      );
    }
  }

  // Login
  Future<void> login({
    required String email,
    required String password,
    bool rememberMe = false,
  }) async {
    try {
      state = state.copyWith(isLoading: true, error: null);

      final apiService = _ref.read(apiServiceProvider);
      final response = await apiService.login({
        'email': email,
        'password': password,
        'remember_me': rememberMe,
      });

      // Store tokens
      await _secureStorage.write(
        key: AppConstants.tokenKey,
        value: response.accessToken,
      );
      await _secureStorage.write(
        key: AppConstants.refreshTokenKey,
        value: response.refreshToken,
      );

      // Store user data
      await _secureStorage.write(
        key: AppConstants.userKey,
        value: response.user.toJson().toString(),
      );

      state = state.copyWith(
        isAuthenticated: true,
        user: response.user,
        isLoading: false,
      );
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
      rethrow;
    }
  }

  // Register
  Future<void> register({
    required String email,
    required String username,
    required String password,
    required String confirmPassword,
    String? firstName,
    String? lastName,
  }) async {
    try {
      state = state.copyWith(isLoading: true, error: null);

      final apiService = _ref.read(apiServiceProvider);
      final response = await apiService.register({
        'email': email,
        'username': username,
        'password': password,
        'confirm_password': confirmPassword,
        'first_name': firstName,
        'last_name': lastName,
      });

      // Store tokens
      await _secureStorage.write(
        key: AppConstants.tokenKey,
        value: response.accessToken,
      );
      await _secureStorage.write(
        key: AppConstants.refreshTokenKey,
        value: response.refreshToken,
      );

      // Store user data
      await _secureStorage.write(
        key: AppConstants.userKey,
        value: response.user.toJson().toString(),
      );

      state = state.copyWith(
        isAuthenticated: true,
        user: response.user,
        isLoading: false,
      );
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
      rethrow;
    }
  }

  // Logout
  Future<void> logout() async {
    try {
      state = state.copyWith(isLoading: true);

      final apiService = _ref.read(apiServiceProvider);
      await apiService.logout();

      await _clearAuthState();
    } catch (e) {
      // Even if logout API call fails, clear local auth state
      await _clearAuthState();
    }
  }

  // Refresh token
  Future<void> refreshToken() async {
    try {
      final refreshToken = await _secureStorage.read(
        key: AppConstants.refreshTokenKey,
      );

      if (refreshToken == null) {
        throw Exception('No refresh token available');
      }

      final apiService = _ref.read(apiServiceProvider);
      final response = await apiService.refreshToken({
        'refresh_token': refreshToken,
      });

      // Update stored tokens
      await _secureStorage.write(
        key: AppConstants.tokenKey,
        value: response.accessToken,
      );
      await _secureStorage.write(
        key: AppConstants.refreshTokenKey,
        value: response.refreshToken,
      );

      state = state.copyWith(user: response.user);
    } catch (e) {
      // If refresh fails, logout
      await _clearAuthState();
      rethrow;
    }
  }

  // Update user profile
  Future<void> updateProfile({
    String? email,
    String? username,
    String? firstName,
    String? lastName,
    String? avatar,
    Map<String, dynamic>? preferences,
  }) async {
    try {
      state = state.copyWith(isLoading: true);

      final apiService = _ref.read(apiServiceProvider);
      final updatedUser = await apiService.getCurrentUser(); // This should be update endpoint

      // Update stored user data
      await _secureStorage.write(
        key: AppConstants.userKey,
        value: updatedUser.toJson().toString(),
      );

      state = state.copyWith(
        user: updatedUser,
        isLoading: false,
      );
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
      rethrow;
    }
  }

  // Clear authentication state
  Future<void> _clearAuthState() async {
    await _secureStorage.delete(key: AppConstants.tokenKey);
    await _secureStorage.delete(key: AppConstants.refreshTokenKey);
    await _secureStorage.delete(key: AppConstants.userKey);

    state = const AuthState(
      isAuthenticated: false,
      user: null,
      isLoading: false,
    );
  }

  // Clear error
  void clearError() {
    state = state.copyWith(error: null);
  }
}

// Current User Provider (for convenient access)
final currentUserProvider = Provider<UserModel?>((ref) {
  return ref.watch(authProvider).user;
});

// Is Authenticated Provider (for convenient access)
final isAuthenticatedProvider = Provider<bool>((ref) {
  return ref.watch(authProvider).isAuthenticated;
});

// Auth Loading Provider (for convenient access)
final authLoadingProvider = Provider<bool>((ref) {
  return ref.watch(authProvider).isLoading;
});

// Auth Error Provider (for convenient access)
final authErrorProvider = Provider<String?>((ref) {
  return ref.watch(authProvider).error;
});