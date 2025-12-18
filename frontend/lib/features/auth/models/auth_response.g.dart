// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'auth_response.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

AuthResponse _$AuthResponseFromJson(Map<String, dynamic> json) => AuthResponse(
  accessToken: json['accessToken'] as String,
  refreshToken: json['refreshToken'] as String,
  tokenType: json['tokenType'] as String,
  expiresIn: (json['expiresIn'] as num).toInt(),
  user: UserModel.fromJson(json['user'] as Map<String, dynamic>),
);

Map<String, dynamic> _$AuthResponseToJson(AuthResponse instance) =>
    <String, dynamic>{
      'accessToken': instance.accessToken,
      'refreshToken': instance.refreshToken,
      'tokenType': instance.tokenType,
      'expiresIn': instance.expiresIn,
      'user': instance.user,
    };

LoginRequest _$LoginRequestFromJson(Map<String, dynamic> json) => LoginRequest(
  email: json['email'] as String,
  password: json['password'] as String,
  rememberMe: json['rememberMe'] as bool?,
);

Map<String, dynamic> _$LoginRequestToJson(LoginRequest instance) =>
    <String, dynamic>{
      'email': instance.email,
      'password': instance.password,
      'rememberMe': instance.rememberMe,
    };

RegisterRequest _$RegisterRequestFromJson(Map<String, dynamic> json) =>
    RegisterRequest(
      email: json['email'] as String,
      username: json['username'] as String,
      password: json['password'] as String,
      confirmPassword: json['confirmPassword'] as String,
      firstName: json['firstName'] as String?,
      lastName: json['lastName'] as String?,
    );

Map<String, dynamic> _$RegisterRequestToJson(RegisterRequest instance) =>
    <String, dynamic>{
      'email': instance.email,
      'username': instance.username,
      'password': instance.password,
      'confirmPassword': instance.confirmPassword,
      'firstName': instance.firstName,
      'lastName': instance.lastName,
    };

RefreshTokenRequest _$RefreshTokenRequestFromJson(Map<String, dynamic> json) =>
    RefreshTokenRequest(refreshToken: json['refreshToken'] as String);

Map<String, dynamic> _$RefreshTokenRequestToJson(
  RefreshTokenRequest instance,
) => <String, dynamic>{'refreshToken': instance.refreshToken};
