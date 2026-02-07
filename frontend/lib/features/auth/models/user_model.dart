import 'package:json_annotation/json_annotation.dart';

part 'user_model.g.dart';

@JsonSerializable()
class UserModel {
  final int id;

  final String email;

  final String? username;

  @JsonKey(name: 'account_name')
  final String? fullName;

  @JsonKey(name: 'avatar_url')
  final String? avatar;

  @JsonKey(name: 'is_superuser')
  final bool isSuperuser;

  @JsonKey(name: 'is_verified')
  final bool isEmailVerified;

  final String? status;

  final DateTime createdAt;

  final DateTime? updatedAt;

  final DateTime? lastLoginAt;

  final Map<String, dynamic>? preferences;

  final List<String>? roles;

  const UserModel({
    required this.id,
    required this.email,
    this.username,
    this.fullName,
    this.avatar,
    required this.isSuperuser,
    required this.isEmailVerified,
    this.status,
    required this.createdAt,
    this.updatedAt,
    this.lastLoginAt,
    this.preferences,
    this.roles,
  });

  factory UserModel.fromJson(Map<String, dynamic> json) =>
      _$UserModelFromJson(json);

  Map<String, dynamic> toJson() => _$UserModelToJson(this);

  bool get isActive => status == 'ACTIVE' || status == 'active';

  UserModel copyWith({
    int? id,
    String? email,
    String? username,
    String? fullName,
    String? avatar,
    bool? isSuperuser,
    bool? isEmailVerified,
    String? status,
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
      fullName: fullName ?? this.fullName,
      avatar: avatar ?? this.avatar,
      isSuperuser: isSuperuser ?? this.isSuperuser,
      isEmailVerified: isEmailVerified ?? this.isEmailVerified,
      status: status ?? this.status,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      lastLoginAt: lastLoginAt ?? this.lastLoginAt,
      preferences: preferences ?? this.preferences,
      roles: roles ?? this.roles,
    );
  }

  String get displayName {
    return fullName ?? username ?? email;
  }

  String get initials {
    final name = fullName ?? username;
    if (name != null && name.isNotEmpty) {
      final parts = name.trim().split(' ');
      if (parts.length >= 2) {
        return '${parts[0][0].toUpperCase()}${parts[1][0].toUpperCase()}';
      }
      return name.substring(0, name.length > 1 ? 2 : 1).toUpperCase();
    }
    return email.substring(0, 2).toUpperCase();
  }
}

