import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../../../features/auth/domain/models/auth_response.dart';
import '../../../features/auth/domain/models/user.dart';
import '../app/config/app_config.dart';

/// 简化版认证服务 - 绕过复杂的 Retrofit 代码生成
/// 使用直接 Dio 调用实现所有认证功能
class SimpleAuthService {
  final Dio _dio = Dio();
  final FlutterSecureStorage _storage = const FlutterSecureStorage();

  SimpleAuthService() {
    _dio.options = BaseOptions(
      baseUrl: '${AppConfig.serverBaseUrl}/api/v1/auth',
      connectTimeout: const Duration(seconds: 30),
      receiveTimeout: const Duration(seconds: 30),
      headers: {'Content-Type': 'application/json'},
    );
  }

  /// 更新 baseUrl（用于后端服务器地址变更时）
  void updateBaseUrl() {
    _dio.options.baseUrl = '${AppConfig.serverBaseUrl}/api/v1/auth';
  }

  /// 注册新用户 - 注意: 后端只返回用户信息，需要额外登录获取token
  Future<AuthResponse> register(String email, String password,
      {String? username, String? fullName}) async {
    final data = {
      'email': email,
      'password': password,
      if (username != null) 'username': username,
      if (fullName != null) 'full_name': fullName,
    };

    try {
      await _dio.post('/register', data: data);
      // After registration, automatically login to get tokens
      return await login(email, password);
    } on DioException catch (e) {
      throw Exception('Registration failed: ${e.response?.data ?? e.message}');
    }
  }

  /// 用户登录
  Future<AuthResponse> login(String emailOrUsername, String password) async {
    final data = {
      'email_or_username': emailOrUsername,
      'password': password,
    };

    try {
      final response = await _dio.post('/login', data: data);
      final responseData = response.data;

      // Convert snake_case to camelCase to match model
      final authResponse = AuthResponse(
        accessToken: responseData['access_token'],
        refreshToken: responseData['refresh_token'],
        tokenType: responseData['token_type'],
        expiresIn: responseData['expires_in'],
      );

      // 保存令牌
      await _storage.write(key: 'access_token', value: authResponse.accessToken);
      await _storage.write(key: 'refresh_token', value: authResponse.refreshToken);

      return authResponse;
    } on DioException catch (e) {
      throw Exception('Login failed: ${e.response?.data ?? e.message}');
    }
  }

  /// 获取当前用户信息
  Future<User> getCurrentUser() async {
    final token = await _storage.read(key: 'access_token');
    if (token == null) throw Exception('No access token available');

    try {
      final response = await _dio.get(
        '/me',
        options: Options(headers: {'Authorization': 'Bearer $token'}),
      );

      // Convert response to User object
      final data = response.data;
      return User(
        id: data['id'].toString(),
        email: data['email'],
        username: data['username'],
        fullName: data['full_name'],
        avatarUrl: data['avatar_url'],
        isVerified: data['is_verified'] ?? false,
        isActive: data['is_active'] ?? true,
        isSuperuser: data['is_superuser'] ?? false,
        createdAt: DateTime.parse(data['created_at']),
      );
    } on DioException catch (e) {
      throw Exception('Get user failed: ${e.response?.data ?? e.message}');
    }
  }

  /// 刷新访问令牌
  Future<AuthResponse> refreshToken(String refreshToken) async {
    try {
      final response = await _dio.post('/refresh', data: {'refresh_token': refreshToken});
      final responseData = response.data;

      final authResponse = AuthResponse(
        accessToken: responseData['access_token'],
        refreshToken: responseData['refresh_token'],
        tokenType: responseData['token_type'],
        expiresIn: responseData['expires_in'],
      );

      // 更新存储
      await _storage.write(key: 'access_token', value: authResponse.accessToken);
      await _storage.write(key: 'refresh_token', value: authResponse.refreshToken);

      return authResponse;
    } on DioException catch (e) {
      throw Exception('Token refresh failed: ${e.response?.data ?? e.message}');
    }
  }

  /// 登出
  Future<void> logout() async {
    final refreshToken = await _storage.read(key: 'refresh_token');
    final accessToken = await _storage.read(key: 'access_token');

    try {
      if (refreshToken != null && accessToken != null) {
        await _dio.post(
          '/logout',
          data: {'refresh_token': refreshToken},
          options: Options(headers: {'Authorization': 'Bearer $accessToken'}),
        );
      }
    } catch (e) {
      // 即使服务器失败也继续清除本地数据
      // Ignored: Server logout failed
    }

    // 清除本地存储
    await _storage.delete(key: 'access_token');
    await _storage.delete(key: 'refresh_token');
  }

  /// 检查认证状态
  Future<bool> checkAuthStatus() async {
    final token = await _storage.read(key: 'access_token');
    if (token == null) return false;

    try {
      await getCurrentUser();
      return true;
    } catch (e) {
      await _storage.delete(key: 'access_token');
      await _storage.delete(key: 'refresh_token');
      return false;
    }
  }
}
