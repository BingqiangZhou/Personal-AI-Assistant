# 音频播放器迁移：audioplayers → just_audio + audio_service

## 基本信息
- **需求ID**: REQ-20260105-001
- **创建日期**: 2026-01-05
- **最后更新**: 2026-01-05
- **负责人**: 产品经理
- **状态**: Active
- **优先级**: High

## 需求描述

### 用户故事
作为播客应用的用户，我想要在使用系统媒体控制（Android 通知栏/控制中心、iOS 锁屏/控制中心、蓝牙/耳机按键）时能够控制播放，以便在不打开应用的情况下方便地管理音频播放。

### 业务价值
- **提升用户体验**：用户可以通过系统原生控制界面管理播放，无需频繁切换到应用
- **符合平台规范**：遵循 Android 和 iOS 的媒体播放最佳实践
- **增强竞争力**：系统媒体控制是现代播客应用的标配功能
- **提高用户留存**：更便捷的播放控制提升用户满意度

### 背景信息
**当前状况**：
- 使用 `audioplayers` 包进行音频播放
- 仅支持应用内 UI 控制
- 无系统媒体通知和控制
- 无法通过蓝牙/耳机按键控制

**用户痛点**：
- 必须打开应用才能控制播放
- 锁屏时无法查看播放信息
- 蓝牙耳机按键无法控制播放
- 无法在系统控制中心快速操作

**技术机会**：
- `just_audio` 提供更强大的音频播放能力
- `audio_service` 提供标准的系统媒体控制集成
- 可以实现后台播放和系统级控制

## 功能需求

### 核心功能
- [FR-001] 将底层播放器从 audioplayers 迁移到 just_audio
- [FR-002] 集成 audio_service 实现系统媒体控制
- [FR-003] 保持现有 UI 交互和业务逻辑完全一致
- [FR-004] 实现 App 内状态与系统状态双向同步
- [FR-005] 支持 Android 和 iOS 平台的系统媒体控制

### 功能详述

#### 功能1：播放器底层迁移
- **描述**：将 audioplayers 替换为 just_audio
- **输入**：音频 URL、播放位置、播放速率
- **处理**：
  - 使用 just_audio 的 AudioPlayer 替代 audioplayers
  - 迁移所有播放控制方法（play, pause, seek, setSpeed）
  - 迁移所有事件监听（position, duration, state）
- **输出**：与原有行为完全一致的播放功能
- **验收标准**：
  - ✅ 播放、暂停、停止功能正常
  - ✅ 进度条拖动准确
  - ✅ 播放速率调整生效
  - ✅ 播放位置保存和恢复正常
  - ✅ UI 状态更新及时准确

#### 功能2：AudioHandler 实现
- **描述**：实现 BaseAudioHandler + SeekHandler
- **输入**：系统媒体控制事件（播放、暂停、快进、快退、seek）
- **处理**：
  - 创建自定义 AudioHandler 类
  - 实现播放控制方法（play, pause, stop, seek）
  - 实现快进快退（rewind 15s, fastForward 30s）
  - 同步播放状态到 playbackState
  - 同步媒体信息到 mediaItem
- **输出**：系统媒体控制可用
- **验收标准**：
  - ✅ AudioHandler 正确初始化
  - ✅ 所有控制方法正确实现
  - ✅ 状态同步及时准确

#### 功能3：Android 系统媒体控制
- **描述**：实现 Android 通知栏和控制中心媒体控制
- **输入**：用户通过系统控制操作
- **处理**：
  - 配置前台服务（mediaPlayback）
  - 创建通知 channel
  - 请求通知权限（Android 13+）
  - 设置 compact actions（播放/暂停、快退、快进）
  - 显示封面、标题、作者等元数据
- **输出**：Android 系统媒体通知和控制
- **验收标准**：
  - ✅ 播放时出现系统媒体通知
  - ✅ 通知显示正确的封面、标题、作者
  - ✅ 播放/暂停按钮工作正常
  - ✅ 快进/快退按钮工作正常（15s/30s）
  - ✅ 进度条可拖动
  - ✅ 点击通知可回到应用
  - ✅ Android 13+ 正确请求通知权限

#### 功能4：iOS 系统媒体控制
- **描述**：实现 iOS 锁屏和控制中心 Now Playing
- **输入**：用户通过系统控制操作
- **处理**：
  - 配置 MPNowPlayingInfoCenter
  - 设置媒体元数据（标题、作者、封面、时长、进度）
  - 实现 MPRemoteCommandCenter 控制
  - 支持播放/暂停、快进/快退、上一首/下一首
- **输出**：iOS Now Playing 界面
- **验收标准**：
  - ✅ 锁屏显示 Now Playing
  - ✅ 控制中心显示媒体卡片
  - ✅ 显示正确的封面、标题、作者
  - ✅ 显示正确的时长和进度
  - ✅ 播放/暂音按钮工作正常
  - ✅ 快进/快退按钮工作正常
  - ✅ 进度条可拖动

#### 功能5：双向状态同步
- **描述**：App 内 UI 与系统控制状态实时同步
- **输入**：来自 App 内或系统控制的操作
- **处理**：
  - 监听 just_audio 的状态流
  - 更新 AudioHandler 的 playbackState
  - 更新 Riverpod 的 AudioPlayerState
  - 触发 UI 重建
- **输出**：双向同步的播放状态
- **验收标准**：
  - ✅ App 内操作立即反映到系统控制
  - ✅ 系统控制操作立即反映到 App UI
  - ✅ 播放位置实时同步
  - ✅ 播放状态（播放/暂停）实时同步

#### 功能6：音频焦点和中断处理
- **描述**：正确处理音频焦点和中断事件
- **输入**：来电、其他应用抢占音频、蓝牙断连等
- **处理**：
  - 监听音频中断事件
  - 暂停播放或降低音量
  - 中断结束后恢复播放
  - 更新 UI 状态
- **输出**：正确的中断处理行为
- **验收标准**：
  - ✅ 来电时自动暂停
  - ✅ 通话结束后可恢复播放
  - ✅ 其他应用抢占音频时正确处理
  - ✅ 蓝牙断连时暂停播放
  - ✅ 状态不混乱

## 非功能需求

### 性能要求
- 播放启动时间：< 2 秒
- UI 状态更新延迟：< 100ms
- 内存占用：不超过原有实现的 120%
- 后台播放稳定性：连续播放 2 小时无崩溃

### 兼容性要求
- **Android**：Android 6.0+ (API 23+)
- **iOS**：iOS 12.0+
- **Flutter**：当前项目使用的 Flutter 版本
- **依赖包**：
  - just_audio: ^0.9.36
  - audio_service: ^0.18.12

### 可用性要求
- 后台播放：支持应用在后台时继续播放
- 系统控制响应：< 200ms
- 错误恢复：网络错误时自动重试

### 安全要求
- 通知权限：Android 13+ 正确请求和处理权限
- 前台服务：正确声明和使用 mediaPlayback 前台服务
- 隐私：不收集额外的用户数据

## 任务分解

### Mobile任务

#### [TASK-M-001] 添加依赖和配置
- **负责人**: Mobile Developer
- **验收标准**:
  - [ ] 添加 just_audio 和 audio_service 依赖
  - [ ] 配置 Android Manifest（前台服务、通知权限）
  - [ ] 配置 iOS Info.plist（后台模式）
  - [ ] 移除 audioplayers 依赖
- **依赖**: 无
- **状态**: Todo

#### [TASK-M-002] 实现 AudioHandler
- **负责人**: Mobile Developer
- **验收标准**:
  - [ ] 创建 PodcastAudioHandler 类
  - [ ] 实现 BaseAudioHandler 和 SeekHandler
  - [ ] 实现播放控制方法（play, pause, stop, seek）
  - [ ] 实现快进快退（rewind 15s, fastForward 30s）
  - [ ] 实现状态同步逻辑
- **依赖**: TASK-M-001
- **状态**: Todo

#### [TASK-M-003] 迁移 AudioPlayerNotifier
- **负责人**: Mobile Developer
- **验收标准**:
  - [ ] 将 audioplayers 替换为 just_audio
  - [ ] 迁移所有播放控制方法
  - [ ] 迁移所有事件监听
  - [ ] 集成 AudioHandler
  - [ ] 保持 AudioPlayerState 模型不变
  - [ ] 保持所有公共 API 不变
- **依赖**: TASK-M-002
- **状态**: Todo

#### [TASK-M-004] 实现 Android 系统媒体控制
- **负责人**: Mobile Developer
- **验收标准**:
  - [ ] 配置通知 channel
  - [ ] 实现通知权限请求（Android 13+）
  - [ ] 设置 compact actions
  - [ ] 设置媒体元数据（封面、标题、作者）
  - [ ] 测试通知显示和控制
- **依赖**: TASK-M-003
- **状态**: Todo

#### [TASK-M-005] 实现 iOS 系统媒体控制
- **负责人**: Mobile Developer
- **验收标准**:
  - [ ] 配置 MPNowPlayingInfoCenter
  - [ ] 设置媒体元数据
  - [ ] 实现 MPRemoteCommandCenter 控制
  - [ ] 测试锁屏和控制中心显示
- **依赖**: TASK-M-003
- **状态**: Todo

#### [TASK-M-006] 实现音频焦点和中断处理
- **负责人**: Mobile Developer
- **验收标准**:
  - [ ] 监听音频中断事件
  - [ ] 实现暂停和恢复逻辑
  - [ ] 处理蓝牙断连
  - [ ] 测试各种中断场景
- **依赖**: TASK-M-003
- **状态**: Todo

#### [TASK-M-007] UI 兼容性验证
- **负责人**: Mobile Developer
- **验收标准**:
  - [ ] 验证所有 UI 组件行为一致
  - [ ] 验证浮动播放器功能
  - [ ] 验证完整播放器功能
  - [ ] 验证播放速率控制
  - [ ] 验证进度条拖动
- **依赖**: TASK-M-003
- **状态**: Todo

### 测试任务

#### [TASK-T-001] 功能测试
- **负责人**: Test Engineer
- **验收标准**:
  - [ ] 测试所有播放控制功能
  - [ ] 测试 Android 系统媒体控制
  - [ ] 测试 iOS 系统媒体控制
  - [ ] 测试双向状态同步
  - [ ] 测试音频中断处理
  - [ ] 测试后台播放
- **依赖**: TASK-M-007
- **状态**: Todo

#### [TASK-T-002] Widget 测试
- **负责人**: Test Engineer
- **验收标准**:
  - [ ] 为 AudioPlayerNotifier 编写单元测试
  - [ ] 为 AudioHandler 编写单元测试
  - [ ] 为播放器 UI 组件编写 widget 测试
  - [ ] 测试覆盖率 > 80%
- **依赖**: TASK-M-007
- **状态**: Todo

#### [TASK-T-003] 真机测试
- **负责人**: Test Engineer
- **验收标准**:
  - [ ] Android 真机测试（多个版本）
  - [ ] iOS 真机测试（多个版本）
  - [ ] 蓝牙耳机测试
  - [ ] 长时间播放稳定性测试
  - [ ] 性能测试（内存、CPU）
- **依赖**: TASK-T-001
- **状态**: Todo

## 验收标准

### 整体验收
- [ ] 所有功能需求已实现
- [ ] 所有测试任务已完成
- [ ] UI 行为与迁移前完全一致
- [ ] Android 和 iOS 系统媒体控制正常工作
- [ ] 双向状态同步正常
- [ ] 音频焦点和中断处理正确
- [ ] 真机测试通过

### 用户验收标准（详细）

#### 1. App 内 UI 行为一致性
- [ ] 播放按钮行为与迁移前一致
- [ ] 暂停按钮行为与迁移前一致
- [ ] 进度条拖动行为与迁移前一致
- [ ] 播放速率调整行为与迁移前一致
- [ ] 快进/快退按钮行为与迁移前一致（-10s/+30s）
- [ ] 浮动播放器显示和交互与迁移前一致
- [ ] 完整播放器展开/收起行为与迁移前一致
- [ ] 播放位置保存和恢复与迁移前一致

#### 2. Android 系统媒体控制
- [ ] 播放时出现系统媒体通知
- [ ] 通知显示正确的封面图
- [ ] 通知显示正确的标题
- [ ] 通知显示正确的作者/播客名称
- [ ] 播放/暂停按钮工作正常
- [ ] 快退按钮工作正常（15s）
- [ ] 快进按钮工作正常（30s）
- [ ] 进度条显示正确
- [ ] 进度条可拖动
- [ ] 点击通知可回到应用
- [ ] Android 13+ 正确请求通知权限
- [ ] 通知在控制中心正确显示

#### 3. iOS 系统媒体控制
- [ ] 播放时出现 Now Playing
- [ ] 锁屏显示 Now Playing
- [ ] 控制中心显示媒体卡片
- [ ] 显示正确的封面图
- [ ] 显示正确的标题
- [ ] 显示正确的作者/播客名称
- [ ] 显示正确的总时长
- [ ] 显示正确的当前进度
- [ ] 播放/暂停按钮工作正常
- [ ] 快退按钮工作正常
- [ ] 快进按钮工作正常
- [ ] 进度条可拖动

#### 4. 双向状态同步
- [ ] App 内点击播放，系统控制立即更新为播放状态
- [ ] 系统控制点击播放，App UI 立即更新为播放状态
- [ ] App 内点击暂停，系统控制立即更新为暂停状态
- [ ] 系统控制点击暂停，App UI 立即更新为暂停状态
- [ ] App 内拖动进度，系统控制进度立即更新
- [ ] 系统控制拖动进度，App UI 进度立即更新
- [ ] 蓝牙耳机按键暂停，App UI 立即更新为暂停状态
- [ ] 蓝牙耳机按键播放，App UI 立即更新为播放状态

#### 5. 音频焦点和中断处理
- [ ] 来电时自动暂停播放
- [ ] 通话结束后可恢复播放（如果用户选择）
- [ ] 其他应用播放音频时正确处理（暂停或降低音量）
- [ ] 蓝牙耳机断连时暂停播放
- [ ] 蓝牙耳机重连后可恢复播放
- [ ] 中断后状态不混乱
- [ ] UI 状态与实际播放状态一致

#### 6. 权限和配置
- [ ] Android 13+ 首次播放时请求通知权限
- [ ] 权限被拒绝时有合理的降级方案
- [ ] Manifest 正确配置前台服务
- [ ] 通知 channel 正确创建
- [ ] iOS Info.plist 正确配置后台模式

#### 7. 元数据显示
- [ ] 封面图正确加载和显示
- [ ] 标题正确显示
- [ ] 作者/播客名称正确显示
- [ ] 时长正确显示
- [ ] 进度正确显示和更新

### 技术验收标准
- [ ] 代码质量达标（flutter analyze 无错误）
- [ ] Widget 测试覆盖率 > 80%
- [ ] 单元测试覆盖率 > 80%
- [ ] 真机测试通过（Android 和 iOS）
- [ ] 性能测试通过（内存、CPU、启动时间）
- [ ] 代码审查通过
- [ ] 文档完整（代码注释、技术文档）

## 设计约束

### 技术约束
- **必须使用**：just_audio, audio_service
- **必须移除**：audioplayers
- **必须保持**：现有的 Riverpod 状态管理架构
- **必须保持**：现有的 AudioPlayerState 模型结构
- **必须保持**：现有的 UI 组件接口

### 业务约束
- **不能改变**：现有的 UI 交互逻辑
- **不能改变**：现有的播放列表管理（虽然当前未实现）
- **不能改变**：现有的播放位置保存逻辑
- **不能影响**：现有的其他功能模块

### 环境约束
- **Android**：最低支持 Android 6.0 (API 23)
- **iOS**：最低支持 iOS 12.0
- **Flutter**：使用项目当前的 Flutter 版本
- **真机测试**：必须在真机上测试，模拟器不足以验证系统媒体控制

## 风险评估

### 技术风险
| 风险项 | 概率 | 影响 | 缓解措施 |
|--------|------|------|----------|
| just_audio 与 audioplayers 行为差异 | 中 | 高 | 详细测试所有播放场景，确保行为一致 |
| audio_service 集成复杂度 | 中 | 高 | 参考官方文档和示例，使用 context7 查询最佳实践 |
| Android 权限处理问题 | 低 | 中 | 遵循 Android 13+ 权限最佳实践 |
| iOS 后台播放限制 | 低 | 中 | 正确配置 Info.plist 和后台模式 |
| 状态同步延迟或不一致 | 中 | 高 | 使用 Stream 监听确保实时同步 |
| 音频中断处理不当 | 中 | 中 | 详细测试各种中断场景 |
| 性能下降 | 低 | 中 | 性能测试和优化 |

### 业务风险
| 风险项 | 概率 | 影响 | 缓解措施 |
|--------|------|------|----------|
| 用户体验变化 | 低 | 高 | 严格保持 UI 行为一致性 |
| 迁移后出现新 bug | 中 | 高 | 全面测试，灰度发布 |
| 用户不习惯系统控制 | 低 | 低 | 提供用户引导 |

## 依赖关系

### 外部依赖
- **just_audio** (^0.9.36) - 音频播放核心库
- **audio_service** (^0.18.12) - 系统媒体控制集成
- **audio_session** - audio_service 的依赖，处理音频会话

### 内部依赖
- **Riverpod** - 状态管理
- **PodcastRepository** - 播放状态同步到服务器
- **PodcastEpisodeModel** - 剧集数据模型
- **AudioPlayerState** - 播放器状态模型

## 实现要点

### 关键改动文件清单
```
frontend/
├── pubspec.yaml                                          # 依赖更新
├── android/
│   └── app/src/main/AndroidManifest.xml                 # 前台服务配置
├── ios/
│   └── Runner/Info.plist                                # 后台模式配置
└── lib/features/podcast/
    ├── presentation/
    │   ├── providers/
    │   │   ├── podcast_providers.dart                   # AudioPlayerNotifier 迁移
    │   │   └── audio_handler.dart                       # 新增：AudioHandler 实现
    │   └── widgets/
    │       ├── audio_player_widget.dart                 # 可能需要微调
    │       ├── floating_player_widget.dart              # 可能需要微调
    │       └── side_floating_player_widget.dart         # 可能需要微调
    └── data/
        └── models/
            └── audio_player_state_model.dart            # 可能需要微调
```

### 核心实现逻辑

#### 1. AudioHandler 实现
```dart
class PodcastAudioHandler extends BaseAudioHandler with SeekHandler {
  final AudioPlayer _player = AudioPlayer();

  // 实现播放控制
  @override
  Future<void> play() async {
    await _player.play();
    // 更新 playbackState
  }

  @override
  Future<void> pause() async {
    await _player.pause();
    // 更新 playbackState
  }

  @override
  Future<void> seek(Duration position) async {
    await _player.seek(position);
    // 更新 playbackState
  }

  // 实现快进快退
  @override
  Future<void> rewind() async {
    final position = _player.position;
    await _player.seek(position - Duration(seconds: 15));
  }

  @override
  Future<void> fastForward() async {
    final position = _player.position;
    await _player.seek(position + Duration(seconds: 30));
  }

  // 监听播放器状态并同步
  void _listenToPlayerState() {
    _player.playerStateStream.listen((state) {
      // 更新 playbackState
    });

    _player.positionStream.listen((position) {
      // 更新 playbackState.updatePosition
    });
  }
}
```

#### 2. AudioPlayerNotifier 迁移
```dart
class AudioPlayerNotifier extends Notifier<AudioPlayerState> {
  AudioHandler? _audioHandler;

  @override
  AudioPlayerState build() {
    _initializeAudioService();
    return AudioPlayerState.initial();
  }

  Future<void> _initializeAudioService() async {
    _audioHandler = await AudioService.init(
      builder: () => PodcastAudioHandler(),
      config: AudioServiceConfig(
        androidNotificationChannelId: 'com.example.app.audio',
        androidNotificationChannelName: 'Audio Playback',
        androidNotificationIcon: 'mipmap/ic_launcher',
      ),
    );
  }

  Future<void> playEpisode(PodcastEpisodeModel episode) async {
    // 设置 MediaItem
    await _audioHandler?.updateMediaItem(MediaItem(
      id: episode.id.toString(),
      title: episode.title,
      artist: episode.podcastTitle,
      artUri: Uri.parse(episode.imageUrl ?? ''),
      duration: Duration(milliseconds: episode.duration ?? 0),
    ));

    // 播放
    await _audioHandler?.play();
  }

  // 其他方法类似迁移
}
```

## 变更记录

| 版本 | 日期 | 变更内容 | 变更人 | 审批人 |
|------|------|----------|--------|--------|
| 1.0 | 2026-01-05 | 初始创建 | 产品经理 | - |

## 相关文档

- [just_audio 官方文档](https://pub.dev/packages/just_audio)
- [audio_service 官方文档](https://pub.dev/packages/audio_service)
- [Android MediaSession 指南](https://developer.android.com/guide/topics/media-apps/working-with-a-media-session)
- [iOS Now Playing 指南](https://developer.apple.com/documentation/mediaplayer/mpnowplayinginfocenter)

## 审批

### 需求评审
- [ ] 产品负责人审批
- [ ] 技术负责人审批
- [ ] 移动端负责人审批

### 上线审批
- [ ] 产品负责人
- [ ] 技术负责人
- [ ] QA 负责人

---

**注意**: 本需求文档是音频播放器迁移的核心指导文档，所有开发和测试工作必须严格遵循本文档的要求。
