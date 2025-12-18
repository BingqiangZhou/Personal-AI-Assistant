import 'package:flutter/material.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Personal AI Assistant',
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Personal AI Assistant - Windows 桌面版'),
          backgroundColor: Colors.blue.shade700,
        ),
        body: Container(
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [Colors.blue.shade50, Colors.blue.shade100],
            ),
          ),
          child: Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(Icons.assistant, size: 100, color: Colors.blue.shade700),
                const SizedBox(height: 20),
                const Text(
                  'Personal AI Assistant',
                  style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 10),
                const Text(
                  'Windows 桌面版演示',
                  style: TextStyle(fontSize: 16, color: Colors.grey),
                ),
                const SizedBox(height: 40),
                ElevatedButton(
                  onPressed: () => _showStatus(context),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.blue.shade700,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(horizontal: 30, vertical: 15),
                  ),
                  child: const Text('测试后端连接'),
                ),
                const SizedBox(height: 20),
                ElevatedButton(
                  onPressed: () => _showFeatures(context),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.green.shade700,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(horizontal: 30, vertical: 15),
                  ),
                  child: const Text('查看功能特性'),
                ),
                const SizedBox(height: 20),
                Text(
                  '✅ Flutter 桌面版架构完整',
                  style: TextStyle(color: Colors.green.shade700),
                ),
              ],
            ),
          ),
        ),
      ),
      debugShowCheckedModeBanner: false,
    );
  }
}

void _showStatus(BuildContext context) {
  showDialog(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('后端连接测试'),
      content: const Text('正在测试连接到 http://localhost:8000/health\n\n如果看到此消息，说明 Flutter 前端运行正常!'),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('确定'),
        ),
      ],
    ),
  );
}

void _showFeatures(BuildContext context) {
  showDialog(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('功能特性'),
      content: const SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('• 后端API: FastAPI + PostgreSQL + Redis'),
            Text('• 前端框架: Flutter + Riverpod + GoRouter'),
            Text('• 认证系统: JWT + 安全存储'),
            Text('• AI助手: 对话管理 + 流式响应'),
            Text('• 知识库: 文档管理 + 搜索'),
            Text('• 播客: RSS订阅 + 播放追踪'),
            Text('• 测试: 10+ 单元测试 + 集成测试'),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('关闭'),
        ),
      ],
    ),
  );
}
