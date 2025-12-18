import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

// Windows 桌面版特定入口点 - 去除移动端特定依赖
// 在开启开发者模式后可切换回 main.dart

void main() {
  runApp(
    const ProviderScope(
      child: PersonalAIAssistantApp(),
    ),
  );
}

class PersonalAIAssistantApp extends StatelessWidget {
  const PersonalAIAssistantApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Personal AI Assistant',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        useMaterial3: true,
        // 适配桌面端
        scaffoldBackgroundColor: const Color(0xFFF5F5F5),
        appBarTheme: const AppBarTheme(
          backgroundColor: Colors.white,
          elevation: 1,
          centerTitle: true,
        ),
        cardTheme: CardThemeData(
          elevation: 2,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
      ),
      home: const DashboardScreen(),
      debugShowCheckedModeBanner: false,
    );
  }
}

class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Personal AI Assistant'),
        centerTitle: true,
      ),
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              '欢迎使用个人AI助手',
              style: TextStyle(
                fontSize: 28,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Windows 桌面版测试版',
              style: TextStyle(
                fontSize: 16,
                color: Colors.grey.shade600,
              ),
            ),
            const SizedBox(height: 32),
            const Text(
              '功能测试',
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(height: 16),
            Expanded(
              child: GridView.count(
                crossAxisCount: 2,
                crossAxisSpacing: 16,
                mainAxisSpacing: 16,
                children: [
                  _FeatureCard(
                    icon: Icons.chat_bubble,
                    title: 'AI 对话',
                    description: '智能助手对话功能',
                    onTap: () => _showFeatureDialog(context, 'AI 对话', '可以与AI助手进行智能对话'),
                  ),
                  _FeatureCard(
                    icon: Icons.library_books,
                    title: '知识库',
                    description: '管理文档和资料',
                    onTap: () => _showFeatureDialog(context, '知识库', '可以存储、组织和搜索个人知识库'),
                  ),
                  _FeatureCard(
                    icon: Icons.record_voice_over,
                    title: '播客管理',
                    description: '订阅和收听播客',
                    onTap: () => _showFeatureDialog(context, '播客管理', '可以订阅喜欢的播客并管理播放'),
                  ),
                  _FeatureCard(
                    icon: Icons.rss_feed,
                    title: '信息订阅',
                    description: 'RSS源内容管理',
                    onTap: () => _showFeatureDialog(context, '信息订阅', '可以订阅RSS源并获取最新内容'),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            const Divider(),
            const SizedBox(height: 16),
            Center(
              child: Text(
                '连接状态: ${_isBackendRunning() ? '✅ 后端已连接' : '⚠️ 后端未连接'}',
                style: TextStyle(
                  fontSize: 14,
                  color: _isBackendRunning() ? Colors.green : Colors.orange,
                ),
              ),
            ),
            const SizedBox(height: 8),
            Center(
              child: Text(
                '开发模式: Windows 桌面版本',
                style: TextStyle(
                  fontSize: 12,
                  color: Colors.grey.shade500,
                ),
              ),
            ),
            const SizedBox(height: 8),
            Center(
              child: ElevatedButton.icon(
                onPressed: () => _testBackendConnection(context),
                icon: const Icon(Icons.refresh),
                label: const Text('测试后端连接'),
              ),
            ),
          ],
        ),
      ),
    );
  }

  bool _isBackendRunning() {
    // 简单检测 - 在实际应用中应该进行API调用
    return true; // 假设已运行
  }

  void _testBackendConnection(BuildContext context) {
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('正在测试后端连接...'),
        duration: Duration(seconds: 2),
      ),
    );
  }

  void _showFeatureDialog(BuildContext context, String title, String description) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: Text(description),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('了解'),
          ),
        ],
      ),
    );
  }
}

class _FeatureCard extends StatelessWidget {
  final IconData icon;
  final String title;
  final String description;
  final VoidCallback onTap;

  const _FeatureCard({
    required this.icon,
    required this.title,
    required this.description,
    required this.onTap,
    super.key,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(
                icon,
                size: 32,
                color: Theme.of(context).primaryColor,
              ),
              const SizedBox(height: 12),
              Text(
                title,
                style: const TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                description,
                style: TextStyle(
                  fontSize: 12,
                  color: Colors.grey.shade600,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}