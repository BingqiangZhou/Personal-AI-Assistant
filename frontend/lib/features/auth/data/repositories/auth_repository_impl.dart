import 'package:dartz/dartz.dart';
import 'package:flutter/foundation.dart';

import '../../domain/models/auth_request.dart';
import '../../domain/models/auth_response.dart';
import '../../domain/models/user.dart';
import '../../domain/repositories/auth_repository.dart';
import '../datasources/auth_remote_datasource.dart';
import '../../../../core/network/exceptions/network_exceptions.dart';
import '../../../../core/storage/secure_storage_service.dart';

class AuthRepositoryImpl implements AuthRepository {
  final AuthRemoteDatasource _remoteDatasource;
  final SecureStorageService _secureStorage;

  AuthRepositoryImpl(
    this._remoteDatasource,
    this._secureStorage,
  );

  @override
  Future<Either<AppException, AuthResponse>> login(LoginRequest request) async {
    try {
      final authResponse = await _remoteDatasource.login(request);

      // Save tokens to secure storage
      await _secureStorage.saveAccessToken(authResponse.accessToken);
      await _secureStorage.saveRefreshToken(authResponse.refreshToken);

      return Right(authResponse);
    } on AppException catch (e) {
      return Left(e);
    } catch (e) {
      return Left(UnknownException(e.toString()));
    }
  }

  @override
  Future<Either<AppException, AuthResponse>> register(RegisterRequest request) async {
    try {
      final authResponse = await _remoteDatasource.register(request);

      // Save tokens to secure storage
      await _secureStorage.saveAccessToken(authResponse.accessToken);
      await _secureStorage.saveRefreshToken(authResponse.refreshToken);

      return Right(authResponse);
    } on AppException catch (e) {
      debugPrint('=== Repository Accepts AppException ===');
      debugPrint('Exception type: ${e.runtimeType}');
      debugPrint('Exception message: ${e.message}');
      return Left(e);
    } catch (e) {
      debugPrint('=== Repository Falls to UnknownException ===');
      debugPrint('Error type: ${e.runtimeType}');
      debugPrint('Error: $e');
      return Left(UnknownException(e.toString()));
    }
  }

  @override
  Future<Either<AppException, RefreshTokenResponse>> refreshToken(String refreshToken) async {
    try {
      final authResponse = await _remoteDatasource.refreshToken(refreshToken);

      // Update tokens in secure storage
      await _secureStorage.saveAccessToken(authResponse.accessToken);
      await _secureStorage.saveRefreshToken(authResponse.refreshToken);

      final refreshResponse = RefreshTokenResponse(
        accessToken: authResponse.accessToken,
        refreshToken: authResponse.refreshToken,
        tokenType: authResponse.tokenType,
        expiresIn: authResponse.expiresIn,
      );

      return Right(refreshResponse);
    } on AppException catch (e) {
      return Left(e);
    } catch (e) {
      return Left(UnknownException(e.toString()));
    }
  }

  @override
  Future<Either<AppException, void>> logout(String? refreshToken) async {
    try {
      // Use provided token or get from storage
      final token = refreshToken ?? await _secureStorage.getRefreshToken();

      // Call logout endpoint with refresh token if available
      if (token != null && token.isNotEmpty) {
        await _remoteDatasource.logout(token);
      }

      // Clear tokens from secure storage
      await _secureStorage.clearTokens();

      return const Right(null);
    } on AppException catch (e) {
      // Even if logout fails, clear local tokens
      await _secureStorage.clearTokens();
      return Left(e);
    } catch (e) {
      // Even if logout fails, clear local tokens
      await _secureStorage.clearTokens();
      return Left(UnknownException(e.toString()));
    }
  }

  @override
  Future<Either<AppException, User>> getCurrentUser() async {
    try {
      final user = await _remoteDatasource.getCurrentUser();
      return Right(user);
    } on AppException catch (e) {
      return Left(e);
    } catch (e) {
      return Left(UnknownException(e.toString()));
    }
  }

  @override
  Future<Either<AppException, void>> forgotPassword(ForgotPasswordRequest request) async {
    try {
      await _remoteDatasource.forgotPassword(request);
      return const Right(null);
    } on AppException catch (e) {
      return Left(e);
    } catch (e) {
      return Left(UnknownException(e.toString()));
    }
  }

  @override
  Future<Either<AppException, void>> resetPassword(ResetPasswordRequest request) async {
    try {
      await _remoteDatasource.resetPassword(request);
      return const Right(null);
    } on AppException catch (e) {
      return Left(e);
    } catch (e) {
      return Left(UnknownException(e.toString()));
    }
  }

  @override
  Future<Either<AppException, void>> verifyEmail(String token) async {
    try {
      await _remoteDatasource.verifyEmail(token);
      return const Right(null);
    } on AppException catch (e) {
      return Left(e);
    } catch (e) {
      return Left(UnknownException(e.toString()));
    }
  }

  @override
  Future<Either<AppException, void>> resendVerificationEmail() async {
    try {
      await _remoteDatasource.resendVerificationEmail();
      return const Right(null);
    } on AppException catch (e) {
      return Left(e);
    } catch (e) {
      return Left(UnknownException(e.toString()));
    }
  }
}