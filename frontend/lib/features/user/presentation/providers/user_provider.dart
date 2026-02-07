import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';
import '../../../../core/network/simple_auth_service.dart';
import '../../../auth/models/user_model.dart';

part 'user_provider.g.dart';

final simpleAuthServiceProvider = Provider<SimpleAuthService>((ref) {
  return SimpleAuthService();
});

@riverpod
class UserNotifier extends _$UserNotifier {
  late SimpleAuthService _authService;

  @override
  AsyncValue<UserModel?> build() {
    _authService = ref.read(simpleAuthServiceProvider);
    _loadUser();
    return const AsyncValue.loading();
  }

  Future<void> _loadUser() async {
    try {
      final user = await _authService.getCurrentUser();
      state = AsyncValue.data(user);
    } catch (e, st) {
      state = AsyncValue.error(e, st);
    }
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    await _loadUser();
  }
}
