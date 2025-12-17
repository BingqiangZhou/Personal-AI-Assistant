"""
最终部署前确认测试

检查所有关键修复是否正确应用，不依赖外部服务
"""

import sys

def test_models():
    '''测试模型定义'''
    print("1. 模型定义测试...")
    try:
        from app.domains.podcast.models import PodcastEpisode, PodcastPlaybackState

        # 检查表名
        assert PodcastEpisode.__tablename__ == "podcast_episodes"
        assert PodcastPlaybackState.__tablename__ == "podcast_playback_states"

        # 检查字段是否存在
        cols = {c.name for c in PodcastEpisode.__table__.columns}
        assert 'metadata_json' in cols, "Python属性必须是metadata_json"
        assert 'metadata' in [c.name for c in PodcastEpisode.__table__.columns], "DB列名应该是metadata"

        print("   [PASS] 模型结构正确")
        print("   - 表名: podcast_episodes, podcast_playback_states")
        print("   - DB列: 'metadata'")
        print("   - Python属性: metadata_json")
        return True
    except Exception as e:
        print(f"   [FAIL] 模型错误: {e}")
        return False

def test_security():
    '''测试安全机制'''
    print("2. 安全机制测试...")
    try:
        from app.core.llm_privacy import ContentSanitizer
        from app.integration.podcast.security import PodcastSecurityValidator

        # 测试隐私净化
        sanitizer = ContentSanitizer('standard')
        result = sanitizer.sanitize("张三 zhangsan@company.com 13800138000", user_id=1, context="test")
        assert "[EMAIL_REDACTED]" in result
        assert "[PHONE_REDACTED]" in result

        # 测试XXE防护
        validator = PodcastSecurityValidator()
        malicious = '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
        valid, error = validator.validate_rss_xml(malicious)
        assert valid == False

        print("   [PASS] 安全机制就绪")
        print("   - 隐私净化: ✓")
        print("   - XXE防护: ✓")
        return True
    except Exception as e:
        print(f"   [FAIL] 安全测试错误: {e}")
        return False

def test_redis_config():
    '''测试Redis配置'''
    print("3. Redis配置测试...")
    try:
        from app.core.redis import PodcastRedis
        from app.core.config import settings

        # 验证配置
        assert settings.REDIS_URL

        # 验证类存在
        redis = PodcastRedis()

        print("   [PASS] Redis配置正确")
        print(f"   - URL: {settings.REDIS_URL}")
        print("   - 类: PodcastRedis")
        return True
    except Exception as e:
        print(f"   [FAIL] Redis错误: {e}")
        return False

def test_api_routes():
    '''测试API路由'''
    print("4. API路由测试...")
    try:
        from app.domains.podcast.api.routes import router
        from fastapi import APIRouter

        assert isinstance(router, APIRouter)
        assert router.prefix == "/podcasts"

        # 检查端点数量
        routes = [r.path for r in router.routes]
        assert any('/subscription' in r for r in routes)
        assert any('/episodes' in r for r in routes)

        print("   [PASS] API路由正确")
        print(f"   - 前缀: {router.prefix}")
        print(f"   - 端点: {len(router.routes)} 条")
        return True
    except Exception as e:
        print(f"   [FAIL] API错误: {e}")
        return False

def test_repositories():
    '''测试仓库层'''
    print("5. 仓库层测试...")
    try:
        from app.domains.podcast.repositories import PodcastRepository

        # 只检查类存在和方法
        methods = ['create_or_update_subscription', 'create_or_update_episode',
                   'update_ai_summary', 'update_playback_progress']

        for method in methods:
            assert hasattr(PodcastRepository, method)

        print("   [PASS] 仓库层完整")
        print(f"   - 核心方法: {len(methods)}个")
        return True
    except Exception as e:
        print(f"   [FAIL] 仓库层错误: {e}")
        return False

def test_services():
    '''测试服务层'''
    print("6. 服务层测试...")
    try:
        from app.domains.podcast.services import PodcastService

        # 检查核心方法
        methods = ['add_subscription', 'generate_summary_for_episode',
                   'update_playback_progress', 'regenerate_summary']

        for method in methods:
            assert hasattr(PodcastService, method)

        print("   [PASS] 服务层完整")
        print(f"   - 核心方法: {len(methods)}个")
        return True
    except Exception as e:
        print(f"   [FAIL] 服务层错误: {e}")
        return False

def test_service_files():
    '''检查关键文件完整性'''
    print("7. 关键文件检查...")
    files_to_check = [
        "app/domains/podcast/models.py",
        "app/domains/podcast/repositories.py",
        "app/domains/podcast/services.py",
        "app/domains/podcast/api/routes.py",
        "app/core/llm_privacy.py",
        "app/integration/podcast/security.py",
    ]

    all_exist = True
    for file in files_to_check:
        import os
        full_path = os.path.join("backend", file.replace("/", os.sep))
        exists = os.path.exists(full_path)
        status = "OK" if exists else "MISSING"
        print(f"   [{status}] {file}")
        all_exist = all_exist and exists

    return all_exist

def main():
    print("=" * 70)
    print("最终部署前确认测试")
    print("=" * 70)
    print()

    results = []

    results.append(test_service_files())
    results.append(test_models())
    results.append(test_security())
    results.append(test_redis_config())
    results.append(test_api_routes())
    results.append(test_repositories())
    results.append(test_services())

    print()
    print("=" * 70)

    passed = sum(results)
    total = len(results)

    if passed == total:
        print(f"[PASS] 最终确认: 全部通过 ({total}/{total})")
        print()
        print("下一步:")
        print("1. docker run -d -p 6379:6379 redis:7-alpine")
        print("2. cd backend && uv run python database_migration.py")
        print("3. uv run uvicorn app.main:app --reload --port 8000")
        print("4. 访问 http://localhost:8000/docs 查看 /podcasts 端点")
        return 0
    else:
        print(f"⚠️  部分通过 ({passed}/{total})")
        return 1

if __name__ == "__main__":
    sys.exit(main())
