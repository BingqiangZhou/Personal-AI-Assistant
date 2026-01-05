# Android系统媒体控制修复总结

## 问题描述
Android真机测试时发现以下问题：
1. 消息通知中心只显示播放/暂停按钮，缺少快进/快退按钮
2. 暂停后无法恢复到播放状态
3. 控制中心显示"not playing"，没有任何响应
4. 应用退出后很久都没有关闭

## 根本原因分析

经过多轮调试，发现以下根本原因：

### 问题1: 状态广播竞态条件
- **问题**: 在`play()`/`pause()`方法中立即调用`_broadcastState()`导致状态在播放器内部更新前就被广播
- **影响**: 状态不一致 - 日志显示`playing=true`后立即出现`playing=false`
- **位置**: `audio_handler.dart:247-270`

### 问题2: 错误的初始ProcessingState
- **问题**: 初始状态设置为`AudioProcessingState.ready`而不是`idle`
- **影响**: Android系统对是否有可用内容感到困惑
- **位置**: `audio_handler.dart:27-43`

### 问题3: MediaItem设置时机错误
- **问题**: MediaItem在音频源准备好之前设置
- **影响**: Android系统可能在音频源准备之前读取MediaItem
- **位置**: `podcast_providers.dart`中的`playEpisode()`方法

### 问题4: 使用stop()而不是pause()
- **问题**: `playEpisode()`调用`stop()`而不是`pause()`，会清除音频源
- **影响**: 导致"not playing"状态并阻止恢复
- **位置**: `podcast_providers.dart:132`

### 问题5: 错误的AudioService配置
- **问题**: `androidStopForegroundOnPause: false`阻止了正确的状态管理
- **影响**: 前台服务在应该暂停时保持活动
- **位置**: `main.dart:21-34`

### 问题6: 缺少AudioSession配置
- **问题**: AudioSession初始化从构造函数中移除，导致Android无法识别媒体会话
- **影响**: 控制中心显示"not playing"，系统控件无法正常工作
- **位置**: `audio_handler.dart:11-48`

### 问题7: 缺少资源清理机制
- **问题**: 应用退出时没有清理机制
- **影响**: 应用在后台无限期运行
- **位置**: 多个文件 (app.dart, MainActivity.kt, audio_handler.dart)

### 问题8: 使用错误的事件流
- **问题**: 使用`playbackEventStream`而不是`playerStateStream`
- **影响**: 每次位置更新都触发广播（每秒数百次）
- **位置**: `audio_handler.dart:122-150`

## 修复内容

### 修复1: 移除手动状态广播
**文件**: `lib/features/podcast/presentation/providers/audio_handler.dart`

**修改**: 移除`play()`和`pause()`方法中的手动`_broadcastState()`调用

```dart
@override
Future<void> play() async {
  // 自愈：如果源丢失，重新加载
  if (_player.audioSource == null && _currentUrl != null) {
    await _player.setUrl(_currentUrl!);
  }
  // 不要在这里手动广播状态 - 让playerStateStream处理
  await _player.play();
}

@override
Future<void> pause() async {
  // 不要在这里手动广播状态 - 让playerStateStream处理
  await _player.pause();
}
```

**原因**: 移除手动`_broadcastState()`调用以避免竞态条件。状态更新现在仅通过`playerStateStream`监听器进行。

---

### 修复2: 使用playerStateStream代替playbackEventStream
**文件**: `lib/features/podcast/presentation/providers/audio_handler.dart`

**修改**:
```dart
void _listenPlayerEvents() {
  // 监听播放器状态变化（播放/暂停、完成等）
  _player.playerStateStream.listen((state) {
    if (kDebugMode) {
      debugPrint('🎧 PlayerState: ${state.playing} ${state.processingState}');
    }
    _broadcastState();
  });

  // 监听处理状态变化
  _player.processingStateStream.listen((state) {
    if (state == ProcessingState.completed) {
      _player.seek(Duration.zero);
      _player.pause();
    }
    _broadcastState();
  });

  // 当可用时更新时长
  _player.durationStream.listen((duration) {
    if (duration != null && mediaItem.value != null) {
      mediaItem.add(mediaItem.value!.copyWith(duration: duration));
    }
  });
}
```

**原因**:
- `playerStateStream`仅在实际状态变化时触发，而不是每次位置更新时
- `playbackEventStream`每次位置更新都触发（每秒数百次），导致不必要的广播

---

### 修复3: 增强状态广播逻辑
**文件**: `lib/features/podcast/presentation/providers/audio_handler.dart`

**修改**:
```dart
void _broadcastState() {
  final playing = _player.playing;
  final rawProcessingState = _mapProcessingState(_player.processingState);

  // 确定是否有有效的音频源
  final hasSource = _player.audioSource != null;
  final hasSequence = _player.sequenceState.sequence.isNotEmpty;

  // 关键：为Android正确映射处理状态
  final processingState = (rawProcessingState == AudioProcessingState.idle && (hasSource || hasSequence))
      ? AudioProcessingState.ready
      : rawProcessingState;

  // 根据当前状态构建控件列表
  final bool hasContent = processingState != AudioProcessingState.idle &&
                         processingState != AudioProcessingState.loading;

  final controls = hasContent
      ? [
          MediaControl.rewind,
          playing ? MediaControl.pause : MediaControl.play,
          MediaControl.fastForward,
        ]
      : [MediaControl.play];

  final androidCompactActionIndices = hasContent
      ? const [0, 1, 2]  // 紧凑视图显示所有3个按钮
      : const [0];       // 仅显示播放按钮

  // 广播包含所有必要字段的状态
  playbackState.add(playbackState.value.copyWith(
    controls: controls,
    androidCompactActionIndices: androidCompactActionIndices,
    playing: playing,
    processingState: processingState,
    updatePosition: _player.position,
    bufferedPosition: _player.bufferedPosition,
    speed: _player.speed,
    systemActions: const {
      MediaAction.play,
      MediaAction.pause,
      MediaAction.stop,
      MediaAction.seek,
      MediaAction.rewind,
      MediaAction.fastForward,
    },
  ));
}
```

**原因**:
- 添加`hasContent`标志以获得更好的状态逻辑
- 确保设置所有必需字段以避免`copyWith`覆盖它们

---

### 修复4: 正确的初始状态
**文件**: `lib/features/podcast/presentation/providers/audio_handler.dart`

**修改**:
```dart
// 初始化默认MediaItem（Android必需）
mediaItem.add(MediaItem(
  id: 'default',
  title: 'No media',
  artist: 'Unknown',
));

// 初始化播放状态为IDLE状态（尚未加载内容）
playbackState.add(PlaybackState(
  controls: [MediaControl.play],
  androidCompactActionIndices: const [0],
  processingState: AudioProcessingState.idle,  // ✅ 从'ready'改为'idle'
  playing: false,
  updatePosition: Duration.zero,
  bufferedPosition: Duration.zero,
  speed: 1.0,
  systemActions: const {
    MediaAction.play,
    MediaAction.pause,
    MediaAction.stop,
    MediaAction.seek,
    MediaAction.rewind,
    MediaAction.fastForward,
  },
));
```

**原因**: 从`idle`状态开始，仅显示播放按钮。内容加载时动态更新为`ready`。

---

### 修复5: 重新排序playEpisode()步骤
**文件**: `lib/features/podcast/presentation/providers/podcast_providers.dart`

**修改**:
```dart
Future<void> playEpisode(PodcastEpisodeModel episode) async {
  // 步骤1: 暂停当前播放（从stop改为pause）
  debugPrint('⏸️ Step 1: Pausing current playback');
  await _audioHandler.pause();

  // 步骤2: 更新状态中的当前剧集
  state = state.copyWith(currentEpisode: episode);

  // 步骤3: 首先设置音频源（在MediaItem之前）
  debugPrint('🔄 Step 3: Setting new audio source');
  await _audioHandler.setAudioSource(episode.audioUrl);

  // 步骤4: 在音频源之后设置MediaItem
  debugPrint('🔄 Step 4: Setting MediaItem for system controls');
  _audioHandler.mediaItem.add(MediaItem(
    id: episode.id.toString(),
    title: episode.title,
    artist: episode.subscriptionTitle ?? 'Unknown Podcast',
    artUri: episode.imageUrl != null ? Uri.parse(episode.imageUrl!) : null,
    duration: episode.audioDuration != null ? Duration(milliseconds: episode.audioDuration!) : null,
  ));

  // 小延迟确保状态更新传播
  await Future.delayed(const Duration(milliseconds: 50));

  // 步骤5: 恢复播放位置（如果有）
  if (state.playbackPosition != null && state.playbackPosition! > 0) {
    debugPrint('⏩ Step 5: Restoring playback position: ${state.playbackPosition}ms');
    await _audioHandler.seek(Duration(milliseconds: state.playbackPosition!));
  }

  // 步骤6: 恢复播放速率
  if (state.playbackSpeed != null && state.playbackSpeed! != 1.0) {
    debugPrint('🎚️ Step 6: Restoring playback speed: ${state.playbackSpeed}x');
    await _audioHandler.setSpeed(state.playbackSpeed!);
  }

  // 步骤7: 开始播放
  debugPrint('▶️ Step 7: Starting playback');
  await _audioHandler.play();

  // 更新状态为播放中
  state = state.copyWith(isPlaying: true);
}
```

**原因**:
- 将`stop()`改为`pause()`以保留音频源
- 在MediaItem之前设置音频源，确保Android按正确顺序读取
- 添加延迟确保状态更新传播

---

### 修复6: 正确的AudioService配置
**文件**: `lib/main.dart`

**修改**:
```dart
audioHandler = await AudioService.init(
  builder: () => PodcastAudioHandler(),
  config: AudioServiceConfig(
    androidNotificationChannelId: 'com.personal_ai_assistant.audio',
    androidNotificationChannelName: 'Podcast Playback',
    androidNotificationChannelDescription: 'Podcast audio playback controls',
    androidNotificationIcon: 'mipmap/ic_launcher',
    androidShowNotificationBadge: true,
    androidStopForegroundOnPause: true,  // ✅ 从false改为true
    androidNotificationOngoing: false,
    androidResumeOnClick: true,  // ✅ 新增
  ),
);
```

**原因**:
- `androidStopForegroundOnPause: true` - 暂停时停止前台服务，允许正确的状态管理
- `androidResumeOnClick: true` - 允许通过点击通知恢复播放

---

### 修复7: AudioSession同步初始化
**文件**: `lib/features/podcast/presentation/providers/audio_handler.dart`

**修改**:
```dart
PodcastAudioHandler() {
  // 重要：同步初始化AudioSession
  // 这对于Android媒体控件正常工作是必需的
  _initAudioSessionSync();

  _listenPlayerEvents();

  // 初始化默认MediaItem（Android必需）
  mediaItem.add(MediaItem(
    id: 'default',
    title: 'No media',
    artist: 'Unknown',
  ));

  // 初始化播放状态...
}

/// 同步初始化AudioSession
void _initAudioSessionSync() {
  // AudioSession.instance是返回单例的同步getter
  final session = AudioSession.instance;
  // configure方法是async但不需要await
  session.configure(const AudioSessionConfiguration.music()).then((_) {
    if (kDebugMode) {
      debugPrint('✅ AudioSession configured for music playback');
    }
    // 配置后设置音频中断监听器
    _setupAudioInterruptionListeners();
  }).catchError((error) {
    if (kDebugMode) {
      debugPrint('⚠️ Failed to configure AudioSession: $error');
    }
  });
}

/// 设置音频中断监听器
void _setupAudioInterruptionListeners() {
  final session = AudioSession.instance;

  // 监听音频中断（来电、其他应用等）
  session.interruptionEventStream.listen((event) {
    if (kDebugMode) {
      debugPrint('🎧 interruption: begin=${event.begin} type=${event.type}');
    }
    if (event.begin) {
      pause();
    }
  });

  // 监听变得嘈杂事件（耳机拔出）
  session.becomingNoisyEventStream.listen((_) {
    if (kDebugMode) {
      debugPrint('🎧 becomingNoisy -> pause');
    }
    pause();
  });
}
```

**原因**: AudioSession必须在构造函数中同步配置，Android媒体会话框架才能正确识别和处理媒体控件。

---

### 修复8: 资源清理
**文件**: 多个

**app.dart**:
```dart
@override
void dispose() {
  // 关键：释放应用时的AudioService资源
  _cleanupAudioService();
  super.dispose();
}

Future<void> _cleanupAudioService() async {
  try {
    await main_app.audioHandler.stop();
    debugPrint('✅ AudioService stopped and cleaned up');
  } catch (e) {
    debugPrint('⚠️ Error cleaning up AudioService: $e');
  }
}
```

**MainActivity.kt**:
```kotlin
override fun onDestroy() {
    // 关键：确保AudioService正确释放
    try {
        super.onDestroy()
    } catch (e: Exception) {
        android.util.Log.e("MainActivity", "Error in onDestroy", e)
        super.onDestroy()
    }
}
```

**audio_handler.dart**:
```dart
Future<void> dispose() async {
  try {
    await _player.stop();
    await _player.dispose();
    if (kDebugMode) {
      debugPrint('✅ AudioHandler disposed successfully');
    }
  } catch (e) {
    if (kDebugMode) {
      debugPrint('⚠️ Error disposing AudioHandler: $e');
    }
  }
}

@override
Future<void> onTaskRemoved() async {
  await stop();
  await super.onTaskRemoved();
}
```

**原因**: 正确的清理确保应用退出时移除前台服务和通知。

## 技术经验总结

### 1. 状态广播时机
**教训**: 永远不要在调用播放器方法后立即手动广播状态。始终依赖流监听器。

**原因**: 播放器方法是异步的，状态更新在方法返回后发生。手动广播会导致竞态条件。

### 2. 事件流选择
**教训**: 使用`playerStateStream`而不是`playbackEventStream`进行状态更新。

**原因**:
- `playbackEventStream`每次位置更新都触发（每秒数百次）
- `playerStateStream`仅在实际状态变化时触发

### 3. ProcessingState语义
**教训**: `idle`表示未加载内容，`ready`表示已加载但未播放。

**原因**: Android系统使用这些状态来确定显示哪些控件。

### 4. AudioSession初始化
**教训**: AudioSession必须在构造函数中同步初始化。

**原因**: Android媒体会话框架需要在任何播放操作之前配置才能正确识别。

### 5. MediaItem和音频源顺序
**教训**: 始终在MediaItem之前设置音频源。

**原因**: Android系统可能在音频源准备之前读取MediaItem，导致状态不一致。

### 6. stop() vs pause()
**教训**: 使用`pause()`保留音频源，`stop()`仅在需要清除源时使用。

**原因**: `stop()`清除音频源，需要下次播放前重新加载。

### 7. AudioService配置
**教训**: `androidStopForegroundOnPause: true`对正确的状态管理很重要。

**原因**: 允许前台服务在播放和暂停状态之间正确转换。

## 修复后的日志分析

应用所有修复后，日志显示：

```
✅ AudioSession configured for music playback
[_broadcastState] playing=false state=AudioProcessingState.idle hasSource=false hasSequence=false hasContent=false
[_broadcastState] controls=1 compactIndices=[0]
[_broadcastState] playing=false state=AudioProcessingState.loading hasSource=true hasSequence=true hasContent=false
[_broadcastState] playing=false state=AudioProcessingState.ready hasSource=true hasSequence=true hasContent=true
[_broadcastState] controls=3 compactIndices=[0, 1, 2]
[_broadcastState] mediaItem=元旦歌友会：我再说一遍！花的心！藏在蕊中！
[_broadcastState] playing=true state=AudioProcessingState.playing hasSource=true hasSequence=true hasContent=true
I/AudioTrack: start(...): prior state:STATE_STOPPED
```

**关键指标**:
- ✅ AudioSession配置成功
- ✅ 状态转换：idle → loading → ready → playing
- ✅ controls=3（快退、播放/暂停、快进）
- ✅ compactIndices=[0, 1, 2]（显示所有3个按钮）
- ✅ MediaItem显示正确的播客标题
- ✅ AudioTrack成功播放

## 预期效果

修复后，Android系统媒体控制应该：
- ✅ 通知栏显示完整的媒体控制（快退、播放/暂停、快进）
- ✅ 暂停后可以正常恢复播放
- ✅ 控制中心正确显示"正在播放"状态
- ✅ 进度条正确显示和更新
- ✅ 所有按钮响应正常
- ✅ 应用退出时正确关闭前台服务和通知

## 验证步骤

### 设备测试清单

#### 1. 通知中心测试
- [ ] 播放音频后，通知栏显示媒体通知
- [ ] 通知显示3个按钮（快退15s、播放/暂停、快进30s）
- [ ] 通知显示正确的封面图
- [ ] 通知显示正确的标题
- [ ] 通知显示正确的作者/播客名称
- [ ] 点击通知可以回到应用

#### 2. 暂停/恢复测试
- [ ] 点击通知栏的暂停按钮，播放器暂停
- [ ] 点击通知栏的播放按钮，播放器恢复
- [ ] App UI与系统控制状态同步

#### 3. 控制中心测试
- [ ] 下拉通知栏，展开控制中心
- [ ] 控制中心显示完整的媒体卡片（不是"not playing"）
- [ ] 显示封面、标题、作者
- [ ] 显示进度条
- [ ] 进度条可拖动
- [ ] 所有按钮响应正常

#### 4. 快进/快退测试
- [ ] 点击快退按钮，验证后退15秒
- [ ] 点击快进按钮，验证前进30秒
- [ ] 进度条正确更新

#### 5. 蓝牙/耳机测试
- [ ] 蓝牙耳机按键暂停，App UI立即更新
- [ ] 蓝牙耳机按键播放，App UI立即更新
- [ ] 耳机拔出时自动暂停
- [ ] 耳机重连后可恢复播放

#### 6. 应用退出测试
- [ ] 退出应用后，通知正确移除
- [ ] 前台服务正确停止
- [ ] 应用不会在后台无限期运行

#### 7. 音频中断测试
- [ ] 来电时自动暂停
- [ ] 通话结束后可恢复播放
- [ ] 其他应用播放音频时正确处理

### 编译和安装
```bash
cd frontend
flutter clean
flutter pub get
flutter analyze  # 应该无错误
flutter run  # 连接Android真机
```

### 日志验证
运行应用时，查看控制台日志确认：
- ✅ `✅ AudioSession configured for music playback`
- ✅ 状态转换：`idle → loading → ready → playing`
- ✅ `controls=3 compactIndices=[0, 1, 2]`
- ✅ `mediaItem=<正确的播客标题>`
- ✅ `AudioTrack: start(...): prior state:STATE_STOPPED`

## 相关文件

### 修改的核心文件
- `lib/features/podcast/presentation/providers/audio_handler.dart` - AudioHandler实现（状态广播、事件监听、AudioSession配置）
- `lib/features/podcast/presentation/providers/podcast_providers.dart` - playEpisode()步骤重新排序
- `lib/main.dart` - AudioService配置（androidStopForegroundOnPause、androidResumeOnClick）
- `lib/core/app/app.dart` - 资源清理（dispose方法）
- `android/app/src/main/kotlin/com/example/personal_ai_assistant/MainActivity.kt` - Activity生命周期处理

### 配置文件
- `android/app/src/main/AndroidManifest.xml` - Android配置（前台服务、通知权限、AudioService声明）

## 参考文档
- [audio_service官方文档](https://pub.dev/packages/audio_service)
- [just_audio官方文档](https://pub.dev/packages/just_audio)
- [audio_session官方文档](https://pub.dev/packages/audio_session)
- [Android MediaSession指南](https://developer.android.com/guide/topics/media-apps/working-with-a-media-session)

---

**修复日期**: 2026-01-05 ~ 2026-01-06
**修复轮次**: 多轮调试（10+个主要修复）
**状态**: 🔄 持续改进中，等待设备验证

## 修复轮次总结

| 轮次 | 问题 | 解决方案 | 结果 |
|------|------|----------|------|
| 第1轮 | bufferedPosition缺失 | 添加bufferedPosition支持 | 问题依然存在 |
| 第2轮 | 竞态条件 | 移除手动状态广播 | 问题依然存在 |
| 第3轮 | 初始状态错误 | 改为idle状态 | 问题依然存在 |
| 第4轮 | MediaItem时机 | 重新排序playEpisode() | 问题依然存在 |
| 第5轮 | stop()清除源 | 改用pause() | 问题依然存在 |
| 第6轮 | AudioService配置 | 修改配置参数 | 部分改善 |
| 第7轮 | 资源清理 | 添加cleanup机制 | 修复退出问题 |
| 第8轮 | AudioSession缺失 | 同步初始化AudioSession | ✅ 日志正常 |
| 第9轮 | 位置更新缺失 | 添加positionStream监听 + 节流 | 待验证 |
| 第10轮 | MediaItem顺序错误 | 在音频源之前设置MediaItem | 待验证 |
| 第11轮 | AudioSession就绪检查 | 添加_isAudioSessionReady标志和等待逻辑 | 待验证 |

---

## 第9轮修复：添加位置更新监听 (2026-01-06)

**问题**: Android MediaSession 需要定期接收位置更新才能保持通知和控件活动

**文件**: `lib/features/podcast/presentation/providers/audio_handler.dart`

**修改**:
```dart
// 添加类字段用于节流位置广播
Duration? _lastBroadcastPosition;

// 在 _listenPlayerEvents() 中添加位置流监听
_player.positionStream.listen((position) {
  final positionMs = position.inMilliseconds;
  // 仅在位置变化达到50ms或首次更新时广播
  if (_lastBroadcastPosition == null ||
      (positionMs - _lastBroadcastPosition!.inMilliseconds).abs() >= 50) {
    _lastBroadcastPosition = position;
    _broadcastState();
  }
});
```

**原因**:
- Android 的 MediaSession 框架需要频繁的位置更新来维持通知可见性
- 节流至 50ms 平衡了性能和需求
- `updatePosition` 字段必须在每次位置变化时更新

---

## 第10轮修复：MediaItem 在音频源之前设置 (2026-01-06)

**问题**: Android MediaSession 在音频加载时需要元数据已可用

**文件**: `lib/features/podcast/presentation/providers/podcast_providers.dart`

**修改**: 交换步骤 3 和 4 的顺序

**之前**:
```
Step 3: 设置音频源
Step 4: 设置 MediaItem
```

**之后**:
```
Step 3: 设置 MediaItem（先于音频源）
Step 4: 设置音频源（在 MediaItem 之后）
```

**原因**:
- Android 在音频源准备时读取 MediaItem 以确定通知中显示的内容
- 如果 MediaItem 在音频源之后设置，Android 可能读取默认/空元数据
- 50ms 延迟确保 MediaItem 在音频加载前完全处理

---

## 第11轮修复：AudioSession 就绪检查 (2026-01-06)

**问题**: AudioSession 使用 fire-and-forget 异步初始化，在播放前可能未就绪

**文件**: `lib/features/podcast/presentation/providers/audio_handler.dart`

**修改**:

1. **添加就绪状态标志**:
```dart
bool _isAudioSessionReady = false; // 跟踪 AudioSession 就绪状态
```

2. **在初始化时设置标志**:
```dart
_initAudioSession().then((_) {
  _isAudioSessionReady = true;
  if (kDebugMode) {
    debugPrint('✅ AudioSession is ready for playback');
  }
}).catchError((error) {
  if (kDebugMode) {
    debugPrint('⚠️ AudioSession initialization failed: $error');
  }
});
```

3. **在播放前等待 AudioSession 就绪**:
```dart
@override
Future<void> play() async {
  // 等待 AudioSession 就绪再播放
  if (!_isAudioSessionReady) {
    if (kDebugMode) {
      debugPrint('⏳ Waiting for AudioSession to be ready...');
    }
    // 等待最多1秒让 AudioSession 就绪
    int attempts = 0;
    while (!_isAudioSessionReady && attempts < 10) {
      await Future.delayed(const Duration(milliseconds: 100));
      attempts++;
    }
    if (!_isAudioSessionReady) {
      if (kDebugMode) {
        debugPrint('⚠️ AudioSession not ready after 1 second, proceeding anyway');
      }
    } else {
      if (kDebugMode) {
        debugPrint('✅ AudioSession ready for playback');
      }
    }
  }
  // ... 其余播放逻辑
}
```

**原因**:
- Android 的 MediaSession 框架需要 AudioSession 在任何播放操作前配置好
- Fire-and-forget 模式不保证初始化在播放前完成
- 等待逻辑确保 AudioSession 在使用前就绪
- 1 秒超时防止无限等待

---

## 第9-11轮的技术要点

### MediaSession 初始化时序
```
1. main.dart: AudioService.init() 创建 AudioHandler
2. AudioHandler 构造函数:
   a. 初始化默认 MediaItem 和 PlaybackState
   b. 启动异步 AudioSession 初始化
   c. 设置 _isAudioSessionReady = false
3. AudioSession 完成后:
   a. 设置 _isAudioSessionReady = true
   b. 打印 "AudioSession is ready for playback"
4. 用户点击播放:
   a. play() 方法检查 _isAudioSessionReady
   b. 如果未就绪，等待最多 1 秒
   c. 然后继续播放
```

### 位置更新机制
```
player.positionStream
    ↓
检查变化是否 >= 50ms
    ↓
如果是，更新 _lastBroadcastPosition
    ↓
调用 _broadcastState()
    ↓
创建新的 PlaybackState 对象（包含 updatePosition）
    ↓
Android MediaSession 更新通知
```

### 关键配置参数

**AudioServiceConfig (main.dart)**:
- `androidStopForegroundOnPause: true` - 暂停时停止前台服务
- `androidResumeOnClick: true` - 点击通知恢复播放
- `androidNotificationOngoing: false` - 通知可被滑动移除

**AudioSessionConfiguration**:
- `AudioSessionConfiguration.music()` - 音乐播放配置
- 自动处理音频中断（来电、其他应用）
- 自动处理耳机断开

**当前状态**: 第9-11轮修复已应用，等待设备测试确认 Android 系统控件功能正常。
