#!/usr/bin/env dart
/**
 * UI结构验证测试
 * 通过分析代码结构验证前端功能完整性
 */

import 'dart:io';

void main() {
  print('🔍 UI结构验证测试开始');
  print('=' * 60);

  int passedTests = 0;
  int totalTests = 0;

  // 测试1: 页面文件存在性
  totalTests++;
  if (testPageFilesExist()) {
    passedTests++;
    print('✅ 测试1: 页面文件存在性 - 通过');
  } else {
    print('❌ 测试1: 页面文件存在性 - 失败');
  }

  // 测试2: 组件文件存在性
  totalTests++;
  if (testComponentFilesExist()) {
    passedTests++;
    print('✅ 测试2: 组件文件存在性 - 通过');
  } else {
    print('❌ 测试2: 组件文件存在性 - 失败');
  }

  // 测试3: 数据模型文件存在性
  totalTests++;
  if (testModelFilesExist()) {
    passedTests++;
    print('✅ 测试3: 数据模型文件存在性 - 通过');
  } else {
    print('❌ 测试3: 数据模型文件存在性 - 失败');
  }

  // 测试4: Provider文件存在性
  totalTests++;
  if (testProviderFilesExist()) {
    passedTests++;
    print('✅ 测试4: Provider文件存在性 - 通过');
  } else {
    print('❌ 测试4: Provider文件存在性 - 失败');
  }

  // 测试5: API服务文件存在性
  totalTests++;
  if (testApiServiceFilesExist()) {
    passedTests++;
    print('✅ 测试5: API服务文件存在性 - 通过');
  } else {
    print('❌ 测试5: API服务文件存在性 - 失败');
  }

  // 测试6: 仓库文件存在性
  totalTests++;
  if (testRepositoryFilesExist()) {
    passedTests++;
    print('✅ 测试6: 仓库文件存在性 - 通过');
  } else {
    print('❌ 测试6: 仓库文件存在性 - 失败');
  }

  // 测试7: 代码生成文件存在性
  totalTests++;
  if (testGeneratedFilesExist()) {
    passedTests++;
    print('✅ 测试7: 代码生成文件存在性 - 通过');
  } else {
    print('❌ 测试7: 代码生成文件存在性 - 失败');
  }

  print('=' * 60);
  print('📊 结果汇总:');
  print('总测试数: $totalTests');
  print('通过: $passedTests');
  print('失败: ${totalTests - passedTests}');
  print('通过率: ${(passedTests / totalTests * 100).toStringAsFixed(1)}%');

  if (passedTests == totalTests) {
    print('\n✅ 所有文件结构验证通过！');
  } else {
    print('\n⚠️ 部分文件缺失，需要检查。');
  }
}

// 测试1: 页面文件存在性
bool testPageFilesExist() {
  final pages = [
    'lib/features/podcast/presentation/pages/podcast_list_page.dart',
    'lib/features/podcast/presentation/pages/podcast_episodes_page.dart',
    'lib/features/podcast/presentation/pages/podcast_episode_detail_page.dart',
    'lib/features/podcast/presentation/pages/podcast_player_page.dart',
  ];

  print('  检查页面文件: ${pages.length}个');

  for (var page in pages) {
    final file = File(page);
    if (!file.existsSync()) {
      print('  缺失: $page');
      return false;
    }
  }

  return true;
}

// 测试2: 组件文件存在性
bool testComponentFilesExist() {
  final components = [
    'lib/features/podcast/presentation/widgets/podcast_subscription_card.dart',
    'lib/features/podcast/presentation/widgets/podcast_episode_card.dart',
    'lib/features/podcast/presentation/widgets/add_podcast_dialog.dart',
    'lib/features/podcast/presentation/widgets/audio_player_widget.dart',
  ];

  print('  检查组件文件: ${components.length}个');

  for (var component in components) {
    final file = File(component);
    if (!file.existsSync()) {
      print('  缺失: $component');
      return false;
    }
  }

  return true;
}

// 测试3: 数据模型文件存在性
bool testModelFilesExist() {
  final models = [
    'lib/features/podcast/data/models/podcast_subscription_model.dart',
    'lib/features/podcast/data/models/podcast_episode_model.dart',
    'lib/features/podcast/data/models/podcast_playback_model.dart',
  ];

  print('  检查模型文件: ${models.length}个');

  for (var model in models) {
    final file = File(model);
    if (!file.existsSync()) {
      print('  缺失: $model');
      return false;
    }
  }

  return true;
}

// 测试4: Provider文件存在性
bool testProviderFilesExist() {
  final providers = [
    'lib/features/podcast/presentation/providers/podcast_providers.dart',
  ];

  print('  检查Provider文件: ${providers.length}个');

  for (var provider in providers) {
    final file = File(provider);
    if (!file.existsSync()) {
      print('  缺失: $provider');
      return false;
    }
  }

  return true;
}

// 测试5: API服务文件存在性
bool testApiServiceFilesExist() {
  final services = [
    'lib/features/podcast/data/services/podcast_api_service.dart',
  ];

  print('  检查服务文件: ${services.length}个');

  for (var service in services) {
    final file = File(service);
    if (!file.existsSync()) {
      print('  缺失: $service');
      return false;
    }
  }

  return true;
}

// 测试6: 仓库文件存在性
bool testRepositoryFilesExist() {
  final repositories = [
    'lib/features/podcast/data/repositories/podcast_repository.dart',
  ];

  print('  检查仓库文件: ${repositories.length}个');

  for (var repo in repositories) {
    final file = File(repo);
    if (!file.existsSync()) {
      print('  缺失: $repo');
      return false;
    }
  }

  return true;
}

// 测试7: 代码生成文件存在性
bool testGeneratedFilesExist() {
  final generated = [
    'lib/features/podcast/data/models/podcast_subscription_model.g.dart',
    'lib/features/podcast/data/models/podcast_episode_model.g.dart',
    'lib/features/podcast/data/models/podcast_playback_model.g.dart',
    'lib/features/podcast/presentation/providers/podcast_providers.g.dart',
    'lib/features/podcast/data/services/podcast_api_service.g.dart',
  ];

  print('  检查生成文件: ${generated.length}个');

  for (var gen in generated) {
    final file = File(gen);
    if (!file.existsSync()) {
      print('  缺失: $gen');
      return false;
    }
  }

  return true;
}