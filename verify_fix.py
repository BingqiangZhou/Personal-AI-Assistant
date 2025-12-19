#!/usr/bin/env python3
import requests
import json

def verify_fix():
    """验证API文档标签修复效果"""
    try:
        response = requests.get("http://localhost:8000/api/v1/openapi.json")
        if response.status_code != 200:
            print(f"无法获取OpenAPI文档: {response.status_code}")
            return False

        data = response.json()

        # 检查播客端点的标签
        errors = []
        podcast_count = 0

        for path, methods in data['paths'].items():
            if 'podcast' in path.lower():
                podcast_count += 1
                for method, details in methods.items():
                    tags = details.get('tags', [])
                    if len(tags) != 1 or tags[0] != 'podcasts':
                        errors.append(f"{method.upper()} {path} -> {tags}")

        print(f"=== 验证结果 ===")
        print(f"播客端点总数: {podcast_count}")
        print(f"标签检查: {'通过' if not errors else '失败'}")

        if errors:
            print("\n发现的问题:")
            for error in errors:
                print(f"  {error}")
            return False
        else:
            print("\n所有播客端点都有正确的单个 'podcasts' 标签")
            print("修复成功！")
            return True

    except Exception as e:
        print(f"验证失败: {e}")
        return False

if __name__ == "__main__":
    verify_fix()