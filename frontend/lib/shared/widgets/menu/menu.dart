// Material 3 自适应菜单组件库
//
// 提供三种自适应菜单实现：
// 1. AdaptiveMenu - 自定义组件，支持完全控制
// 2. AdaptiveScaffoldMenu - 基于 flutter_adaptive_scaffold
// 3. M3AdaptiveMenu - 增强版 Material 3 菜单
//
// 特性：
// - Material 3 设计规范
// - 响应式布局（移动端、平板、桌面端）
// - 支持折叠/展开
// - 徽章通知
// - 快捷键提示
// - 用户菜单集成
// - 暗色模式支持
// - 模态抽屉（移动端）
// - 键盘快捷键
// - 无障碍访问

// 基础组件
export 'adaptive_menu.dart'
    show
        AdaptiveMenu,
        AdaptiveMenuConfig,
        MenuItem,
        MenuDivider;

export 'adaptive_scaffold_menu.dart'
    show
        AdaptiveScaffoldMenu,
        NavigationDestinationHelper;

// 增强版 Material 3 组件
export 'material3_menu.dart'
    show
        M3AdaptiveMenu,
        M3MenuConfig,
        M3MenuItem,
        M3MenuDivider,
        M3MenuGroup;

// 演示页面
export 'demo_page.dart'
    show
        AdaptiveMenuDemoPage,
        CustomAdaptiveMenuPage,
        ScaffoldAdaptiveMenuPage;

export 'material3_demo.dart'
    show
        M3MenuDemoPage,
        M3MenuStandalonePage;
