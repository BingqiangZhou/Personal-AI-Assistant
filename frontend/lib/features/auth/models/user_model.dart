import 'package:json_annotation/json_annotation.dart';

part 'user_model.g.dart';

@JsonSerializable()
class UserModel {
  final int id;  // Match backend: int
  final String email;
  final String? username;  // Can be null from backend
  final String? avatar;  // avatar_url from backend
  @JsonKey(defaultValue: false)
  final bool isActive;  // is_active from backend

  @JsonKey(defaultValue: false)
  final bool isEmailVerified;  // is_verified from backend
  final DateTime createdAt;
  final DateTime? updatedAt;  // Optional since backend doesn't return this
  final DateTime? lastLoginAt;  // Optional
  final Map<String, dynamic>? preferences;  // Optional
  final List<String>? roles;  // Optional

  const UserModel({
    required this.id,
    required this.email,
    this.username,
    this.avatar,
    required this.isActive,
    required this.isEmailVerified,
    required this.createdAt,
    this.updatedAt,
    this.lastLoginAt,
    this.preferences,
    this.roles,
  });

  factory UserModel.fromJson(Map<String, dynamic> json) =>
      _$UserModelFromJson(json);

  Map<String, dynamic> toJson() => _$UserModelToJson(this);

  UserModel copyWith({
    int? id,
    String? email,
    String? username,
    String? avatar,
    bool? isActive,
    bool? isEmailVerified,
    DateTime? createdAt,
    DateTime? updatedAt,
    DateTime? lastLoginAt,
    Map<String, dynamic>? preferences,
    List<String>? roles,
  }) {
    return UserModel(
      id: id ?? this.id,
      email: email ?? this.email,
      username: username ?? this.username,
      avatar: avatar ?? this.avatar,
      isActive: isActive ?? this.isActive,
      isEmailVerified: isEmailVerified ?? this.isEmailVerified,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      lastLoginAt: lastLoginAt ?? this.lastLoginAt,
      preferences: preferences ?? this.preferences,
      roles: roles ?? this.roles,
    );
  }

  String get displayName {
    return username ?? email;
  }

  String get initials {
    if (username != null && username!.isNotEmpty) {
      return username!.substring(0, 2).toUpperCase();
    }
    return email.substring(0, 2).toUpperCase();
  }
}

