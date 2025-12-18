#!/usr/bin/env python3
"""
Personal AI Assistant - 启动器
为了解决 Flutter 项目目录层级问题
"""
import os
import subprocess
import sys

PROJECT_DIR = r"E:\Projects\AI\PersonalKnowledgeLibrary\Claude\personal-ai-assistant"
FRONTEND_DIR = os.path.join(PROJECT_DIR, "frontend")
MOBILE_DIR = os.path.join(FRONTEND_DIR, "mobile")

def run_flutter_windows():
    """尝试运行 Windows 桌面版本"""
    print("=" * 70)
    print("🚀 Personal AI Assistant - Windows 桌面版启动器")
    print("=" * 70)

    os.chdir(FRONTEND_DIR)
    print(f"✅ 工作目录: {os.getcwd()}")

    # 检查是否已开启开发者模式
    print("\n[1] 检查 Windows 开发者模式...")
    print("如果遇到 'symlink support' 错误，请:")
    print("   1. 按 Win+I 打开设置")
    print("   2. 搜索 '开发者模式'")
    print("   3. 开启 '使用开发人员功能'")

    print("\n[2] 尝试运行 Windows 应用...")
    try:
        result = subprocess.run(
            ["flutter", "run", "-d", "windows", "--debug"],
            cwd=FRONTEND_DIR,
            timeout=300,
            capture_output=False
        )
        if result.returncode == 0:
            print("✅ Windows 应用已启动!")
        else:
            print("❌ Windows 启动失败，尝试浏览器模式...")
            run_flutter_web()
    except subprocess.TimeoutExpired:
        print("⏰ 超时，应用可能在运行中...")
    except Exception as e:
        print(f"❌ 错误: {e}")
        run_flutter_web()

def run_flutter_web():
    """运行 Web 版本作为备选方案"""
    print("\n" + "=" * 70)
    print("🌐 转换为浏览器模式 (推荐备选方案)")
    print("=" * 70)

    os.chdir(MOBILE_DIR)
    print(f"✅ 进入子目录: {os.getcwd()}")

    print("\n[1] 启动 Flutter Web 开发服务器...")
    print(" http://localhost:8080")
    print("\n[2] 等待编译完成...")
    print(" 按 Ctrl+C 停止")

    try:
        subprocess.run(
            ["flutter", "run", "-d", "chrome", "--web-port=8080"],
            cwd=MOBILE_DIR,
            timeout=120
        )
    except KeyboardInterrupt:
        print("\n\n已停止")
    except Exception as e:
        print(f"错误: {e}")
        print("\n请手动执行: cd frontend/mobile && flutter run -d chrome")

def run_browser_only():
    """仅提示浏览器方式"""
    print("\n" + "=" * 70)
    print("📋 快速运行方案")
    print("=" * 70)
    print("\n由于 Windows 桌面构建需要"开发者模式"，")
    print("当前最简单的方法是使用浏览器版本。\n")
    print("请在命令行中执行:")
    print("  cd frontend/mobile")
    print("  flutter run -d chrome")
    print("\n或直接访问: http://localhost:8080 (运行后)")
    print("\n" + "=" * 70)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--browser":
        run_browser_only()
    else:
        run_flutter_windows()
