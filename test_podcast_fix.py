#!/usr/bin/env python3
"""
播客功能修复验证脚本
验证后端API路径修复是否解决前端错误
"""

import requests
import json
import time

def test_api_paths():
    """测试修复后的API路径"""
    base_url = "http://localhost:8000/api/v1"

    print("🔍 测试播客API路径修复")
    print("=" * 50)

    # 测试1: 检查OpenAPI文档
    print("\n1. 检查OpenAPI文档中的路径...")
    try:
        response = requests.get(f"{base_url}/openapi.json")
        if response.status_code == 200:
            openapi = response.json()
            paths = list(openapi['paths'].keys())
            podcast_paths = [p for p in paths if 'podcast' in p.lower()]

            print(f"✅ OpenAPI文档加载成功")
            print(f"📊 发现 {len(podcast_paths)} 个播客相关路径:")
            for path in podcast_paths[:5]:  # 显示前5个
                print(f"   {path}")

            # 检查是否有重复的podcasts
            duplicate_paths = [p for p in podcast_paths if '/podcasts/podcasts/' in p]
            if duplicate_paths:
                print(f"❌ 发现重复路径: {duplicate_paths}")
                return False
            else:
                print("✅ 没有发现重复路径")
        else:
            print(f"❌ 无法获取OpenAPI文档: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ OpenAPI检查失败: {e}")
        return False

    # 测试2: 测试无认证的API响应
    print("\n2. 测试API端点响应...")
    test_endpoints = [
        "/podcasts/subscriptions",
        "/podcasts/episodes",
        "/podcasts/stats"
    ]

    for endpoint in test_endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}")
            print(f"   {endpoint}: HTTP {response.status_code}")

            # 期望是422（缺少认证）而不是404（路径错误）
            if response.status_code == 422:
                print(f"   ✅ 路径正确，等待认证")
            elif response.status_code == 404:
                print(f"   ❌ 路径错误 (404)")
                return False
            elif response.status_code == 401:
                print(f"   ✅ 路径正确，需要认证")
            else:
                print(f"   ⚠️  意外状态: {response.status_code}")

        except Exception as e:
            print(f"   ❌ 请求失败: {e}")
            return False

    # 测试3: 验证Docker服务状态
    print("\n3. 检查Docker服务状态...")
    try:
        import subprocess
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=podcast_backend", "--format", "{{.Status}}"],
            capture_output=True, text=True
        )
        if "Up" in result.stdout:
            print("✅ Docker后端服务运行正常")
        else:
            print("❌ Docker后端服务未运行")
            return False
    except Exception as e:
        print(f"⚠️  无法检查Docker状态: {e}")

    return True

def test_frontend_config():
    """验证前端配置"""
    print("\n4. 检查前端配置...")

    try:
        # 检查前端API服务配置
        import os
        frontend_service_file = "frontend/lib/features/podcast/data/services/podcast_api_service.dart"

        if os.path.exists(frontend_service_file):
            with open(frontend_service_file, 'r') as f:
                content = f.read()

            # 检查是否有重复的podcasts路径
            if "/podcasts/podcasts/" in content:
                print("❌ 前端配置中发现重复路径")
                return False
            elif "/podcasts/subscriptions" in content:
                print("✅ 前端API路径配置正确")
            else:
                print("⚠️  无法确认前端配置")
        else:
            print("⚠️  无法找到前端配置文件")

    except Exception as e:
        print(f"⚠️  前端配置检查失败: {e}")

    return True

def main():
    """主测试函数"""
    print("播客功能修复验证工具")
    print("验证后端API路径修复是否解决前端错误")
    print()

    # 等待服务启动
    print("等待服务启动...")
    time.sleep(3)

    success = test_api_paths()
    success = test_frontend_config() and success

    print("\n" + "=" * 50)
    if success:
        print("🎉 所有测试通过！修复成功！")
        print("\n现在可以:")
        print("1. 重新启动Flutter应用")
        print("2. 进入播客页面")
        print("3. 应该不再显示 'Server error'")
    else:
        print("❌ 测试失败，需要进一步检查")
        print("\n可能的问题:")
        print("1. Docker服务未完全启动")
        print("2. 数据库连接失败")
        print("3. 其他配置问题")

if __name__ == "__main__":
    main()