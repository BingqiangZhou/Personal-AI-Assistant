// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'auth_request.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

LoginRequest _$LoginRequestFromJson(Map<String, dynamic> json) => LoginRequest(
  username: json['email_or_username'] as String,
  password: json['password'] as String,
);

Map<String, dynamic> _$LoginRequestToJson(LoginRequest instance) =>
    <String, dynamic>{
      'email_or_username': instance.username,
      'password': instance.password,
    };

RegisterRequest _$RegisterRequestFromJson(Map<String, dynamic> json) =>
    RegisterRequest(
      email: json['email'] as String,
      password: json['password'] as String,
      username: json['username'] as String?,
    );

Map<String, dynamic> _$RegisterRequestToJson(RegisterRequest instance) =>
    <String, dynamic>{
      'email': instance.email,
      'password': instance.password,
      'username': instance.username,
    };

RefreshTokenRequest _$RefreshTokenRequestFromJson(Map<String, dynamic> json) =>
    RefreshTokenRequest(refreshToken: json['refresh_token'] as String);

Map<String, dynamic> _$RefreshTokenRequestToJson(
  RefreshTokenRequest instance,
) => <String, dynamic>{'refresh_token': instance.refreshToken};

ForgotPasswordRequest _$ForgotPasswordRequestFromJson(
  Map<String, dynamic> json,
) => ForgotPasswordRequest(email: json['email'] as String);

Map<String, dynamic> _$ForgotPasswordRequestToJson(
  ForgotPasswordRequest instance,
) => <String, dynamic>{'email': instance.email};

ResetPasswordRequest _$ResetPasswordRequestFromJson(
  Map<String, dynamic> json,
) => ResetPasswordRequest(
  token: json['token'] as String,
  email: json['email'] as String,
  password: json['password'] as String,
  passwordConfirmation: json['password_confirmation'] as String,
);

Map<String, dynamic> _$ResetPasswordRequestToJson(
  ResetPasswordRequest instance,
) => <String, dynamic>{
  'token': instance.token,
  'email': instance.email,
  'password': instance.password,
  'password_confirmation': instance.passwordConfirmation,
};
