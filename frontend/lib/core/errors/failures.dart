import 'package:equatable/equatable.dart';

abstract class Failure extends Equatable {
  const Failure([List properties = const <dynamic>[]]);
}

class ServerFailure extends Failure {
  final String message;
  final String? code;
  final int? statusCode;

  const ServerFailure(
    this.message, {
    this.code,
    this.statusCode,
  });

  @override
  List<Object?> get props => [message, code, statusCode];
}

class NetworkFailure extends Failure {
  final String message;
  final String? code;

  const NetworkFailure(
    this.message, {
    this.code,
  });

  @override
  List<Object?> get props => [message, code];
}

class CacheFailure extends Failure {
  final String message;
  final String? code;

  const CacheFailure(
    this.message, {
    this.code,
  });

  @override
  List<Object?> get props => [message, code];
}

class ValidationFailure extends Failure {
  final String message;
  final Map<String, List<String>>? fieldErrors;
  final String? code;

  const ValidationFailure(
    this.message, {
    this.fieldErrors,
    this.code,
  });

  @override
  List<Object?> get props => [message, fieldErrors, code];
}

class AuthenticationFailure extends Failure {
  final String message;
  final String? code;

  const AuthenticationFailure(
    this.message, {
    this.code,
  });

  @override
  List<Object?> get props => [message, code];
}

class AuthorizationFailure extends Failure {
  final String message;
  final String? code;

  const AuthorizationFailure(
    this.message, {
    this.code,
  });

  @override
  List<Object?> get props => [message, code];
}

class NotFoundFailure extends Failure {
  final String message;
  final String? code;

  const NotFoundFailure(
    this.message, {
    this.code,
  });

  @override
  List<Object?> get props => [message, code];
}

class UnknownFailure extends Failure {
  final String message;
  final String? code;
  final int? statusCode;

  const UnknownFailure(
    this.message, {
    this.code,
    this.statusCode,
  });

  @override
  List<Object?> get props => [message, code, statusCode];
}