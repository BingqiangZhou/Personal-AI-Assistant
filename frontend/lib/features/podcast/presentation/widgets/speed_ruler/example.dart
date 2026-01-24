// 倍速播放控件使用示例
// Speed Ruler Widget Usage Examples

import 'package:flutter/material.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/speed_ruler/speed_ruler.dart';

// ============================================
// 示例 1: 基本使用（底部弹窗）
// Example 1: Basic Usage (Bottom Sheet)
// ============================================

class BasicUsageExample extends StatelessWidget {
  const BasicUsageExample({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Basic Usage')),
      body: Center(
        child: FilledButton(
          onPressed: () async {
            // 显示倍速选择弹窗
            final selectedSpeed = await SpeedRulerSheet.show(
              context: context,
              initialValue: 1.5,
              onSpeedChanged: (speed) {
                // TODO: Handle speed change
                // print('Speed changed: $speed');
              },
            );

            // 处理用户选择
            if (selectedSpeed != null) {
              // TODO: Handle final speed selection
              // print('Final speed: $selectedSpeed');
            }
          },
          child: const Text('选择倍速 / Select Speed'),
        ),
      ),
    );
  }
}

// ============================================
// 示例 2: 嵌入式使用（直接在页面中）
// Example 2: Embedded Usage (Direct in Page)
// ============================================

class EmbeddedUsageExample extends StatefulWidget {
  const EmbeddedUsageExample({super.key});

  @override
  State<EmbeddedUsageExample> createState() => _EmbeddedUsageExampleState();
}

class _EmbeddedUsageExampleState extends State<EmbeddedUsageExample> {
  double _currentSpeed = 1.5;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Embedded Usage')),
      body: Column(
        children: [
          // 显示当前速度
          Padding(
            padding: const EdgeInsets.all(24),
            child: Text(
              '当前速度: ${_currentSpeed.toStringAsFixed(1)}x',
              style: const TextStyle(fontSize: 24),
            ),
          ),

          // 直接嵌入 SpeedRuler 组件
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 24),
            child: SpeedRuler(
              value: _currentSpeed,
              onChanged: (value) {
                setState(() {
                  _currentSpeed = value;
                });
              },
            ),
          ),
        ],
      ),
    );
  }
}

// ============================================
// 示例 3: 自定义范围和步长
// Example 3: Custom Range and Step
// ============================================

class CustomRangeExample extends StatelessWidget {
  const CustomRangeExample({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Custom Range')),
      body: Center(
        child: FilledButton(
          onPressed: () async {
            await SpeedRulerSheet.show(
              context: context,
              title: '自定义范围',
              initialValue: 1.0,
              min: 0.8,        // 自定义最小值
              max: 2.0,        // 自定义最大值
              step: 0.2,       // 自定义步长
              majorStep: 0.4,  // 自定义主要刻度间隔
              onSpeedChanged: (speed) {
                // TODO: Handle custom speed change
                // print('Custom speed: $speed');
              },
            );
          },
          child: const Text('自定义范围选择'),
        ),
      ),
    );
  }
}

// ============================================
// 示例 4: 集成到音频播放器
// Example 4: Integration with Audio Player
// ============================================

class AudioPlayerIntegrationExample extends StatefulWidget {
  const AudioPlayerIntegrationExample({super.key});

  @override
  State<AudioPlayerIntegrationExample> createState() =>
      _AudioPlayerIntegrationExampleState();
}

class _AudioPlayerIntegrationExampleState
    extends State<AudioPlayerIntegrationExample> {
  // 模拟音频播放器状态
  double _playbackSpeed = 1.0;
  bool _isPlaying = false;

  // 显示速度选择器
  void _showSpeedSelector() async {
    final selectedSpeed = await SpeedRulerSheet.show(
      context: context,
      initialValue: _playbackSpeed,
      title: '播放速度',
      onSpeedChanged: (speed) {
        // 实时更新播放速度（无需等待确认）
        setState(() {
          _playbackSpeed = speed;
        });
        // TODO: 调用实际的音频播放器 API
        // _audioPlayer.setSpeed(speed);
      },
    );

    if (selectedSpeed != null) {
      // TODO: Handle speed confirmation
      // print('Speed confirmed: $selectedSpeed');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Audio Player')),
      body: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          // 播放控制
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              IconButton(
                iconSize: 64,
                onPressed: () {
                  setState(() {
                    _isPlaying = !_isPlaying;
                  });
                },
                icon: Icon(_isPlaying ? Icons.pause : Icons.play_arrow),
              ),
            ],
          ),

          const SizedBox(height: 32),

          // 当前速度显示
          Text(
            '播放速度: ${_playbackSpeed.toStringAsFixed(1)}x',
            style: const TextStyle(fontSize: 20),
          ),

          const SizedBox(height: 16),

          // 速度选择按钮
          FilledButton.tonalIcon(
            onPressed: _showSpeedSelector,
            icon: const Icon(Icons.speed),
            label: const Text('调整速度'),
          ),
        ],
      ),
    );
  }
}

// ============================================
// 示例 5: 查看演示页面
// Example 5: View Demo Page
// ============================================

class ViewDemoPageExample extends StatelessWidget {
  const ViewDemoPageExample({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Demo Page')),
      body: Center(
        child: FilledButton(
          onPressed: () {
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (context) => const SpeedRulerDemoPage(),
              ),
            );
          },
          child: const Text('查看完整演示'),
        ),
      ),
    );
  }
}
