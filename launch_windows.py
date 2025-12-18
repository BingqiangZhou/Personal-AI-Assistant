#!/usr/bin/env python3
"""
Personal AI Assistant - Windows 桌面版启动器
Python 版本启动器，提供更好的环境控制
"""

import os
import subprocess
import sys
import time

PROJECT_DIR = r"E:\Projects\AI\PersonalKnowledgeLibrary\Claude\personal-ai-assistant"
FRONTEND_DIR = os.path.join(PROJECT_DIR, "frontend")

def print_section(title):
    print("=" * 60)
    print(title)
    print("=" * 60)

def run_command(cmd, cwd=None, timeout=120):
    """运行命令并返回结果"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "命令超时"
    except Exception as e:
        return False, "", str(e)

def check_flutter_environment():
    """检查 Flutter 环境"""
    print_section("检查 Flutter 环境")

    success, stdout, stderr = run_command("flutter --version")
    if success:
        print("✅ Flutter 已安装")
        print(stdout)
    else:
        print("❌ Flutter 未安装或未在 PATH 中")
        return False

    success, stdout, stderr = run_command("flutter devices")
    if success:
        print("✅ 设备列表:")
        print(stdout)
        # 检查是否有 Windows 设备
        if "windows" in stdout.lower():
            print("✅ Windows 设备可用")
        else:
            print("⚠️ 未检测到 Windows 设备")
    else:
        print("❌ 无法获取设备列表")
        print(stderr)

    return True

def check_backend():
    """检查后端是否运行"""
    print_section("检查后端服务")

    success, stdout, stderr = run_command("curl -s http://localhost:8000/health")
    if success and "healthy" in stdout:
        print("✅ 后端服务运行正常")
        print(f"响应: {stdout.strip()}")
        return True
    else:
        print("⚠️ 后端服务未运行或不健康")
        print("请确保 Docker 容器正在运行")
        return False

def run_windows_desktop():
    """尝试运行 Windows 桌面版"""
    print_section("尝试启动 Windows 桌面版")

    os.chdir(FRONTEND_DIR)
    print(f"当前目录: {os.getcwd()}")

    print("\n正在尝试构建 Windows 版本...")
    print("注意: 这可能需要开启 Windows 开发者模式")

    # 运行 Flutter 命令
    success, stdout, stderr = run_command(
        "flutter run -d windows --target=lib/main_windows.dart",
        timeout=60
    )

    if success:
        print("✅ Windows 桌面版启动成功!")
        print(stdout)
        return True
    else:
        print("❌ Windows 桌面版启动失败")
        print("\n错误信息:")
        print(stderr)

        if "symlink support" in stderr.lower():
            print("\n解决方案:")
            print("1. 按 Win+I 打开设置")
            print("2. 搜索 '开发者模式'")
            print("3. 开启 '使用开发人员功能'")
            print("4. 重新运行此脚本")

        return False

def run_web_version():
    """运行 Web 版本作为备选"""
    print_section("启动 Web 版本作为备选方案")

    print("\n正在启动 Flutter Web 版本...")
    print("这将在浏览器中打开应用")

    os.chdir(os.path.join(FRONTEND_DIR, "mobile"))
    print(f"切换到目录: {os.getcwd()}")

    print("\n启动命令: flutter run -d chrome --web-port=8080")
    print("应用将在 http://localhost:8080 上运行")
    print("\n按 Ctrl+C 停止服务器")

    # 运行并显示输出
    try:
        process = subprocess.Popen(
            ["flutter", "run", "-d", "chrome", "--web-port=8080"],
            cwd=os.path.join(FRONTEND_DIR, "mobile"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        print("\nFlutter 正在构建应用...")

        # 实时显示输出
        for line in process.stdout:
            print(line.rstrip())

            # 检查是否已启动
            if "Waiting for connection from debug service" in line:
                print("\n✅ 应用已启动!")
                print("请访问 http://localhost:8080")
                print("\n如要停止服务器，请按 Ctrl+C")
                break

        # 等待用户停止
        process.wait()

    except KeyboardInterrupt:
        print("\n正在停止服务器...")
        process.terminate()
        process.wait()
    except Exception as e:
        print(f"错误: {e}")

def main():
    """主函数"""
    print_section("Personal AI Assistant - Windows 桌面版启动器")
    print("版本: 1.0")
    print("时间:", time.strftime("%Y-%m-%d %H:%M:%S"))

    # 检查环境
    if not check_flutter_environment():
        input("\n按回车键退出...")
        return

    print()

    # 检查后端
    check_backend()

    print("\n")

    # 尝试 Windows 桌面版
    if run_windows_desktop():
        input("\n应用运行中，按回车键退出...")
        return

    print("\n" + "="*60)
    print("Windows 桌面版启动失败，尝试 Web 版本作为备选方案")
    print("="*60 + "\n")

    # 运行 Web 版本
    run_web_version()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n用户取消操作")
    except Exception as e:
        print(f"\n程序出错: {e}")

    input("\n按回车键退出...")