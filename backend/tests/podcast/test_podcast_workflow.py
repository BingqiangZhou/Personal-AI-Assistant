"""
快速播客功能测试脚本

包含：
1. 安全模块测试
2. 模型导入测试
3. 简单工作流验证
"""

import asyncio
import sys

# 测试1: 安全模块导入
def test_security():
    print("TEST: Security module...")
    try:
        from app.core.llm_privacy import ContentSanitizer
        from app.domains.podcast.integration.security import PodcastSecurityValidator

        sanitizer = ContentSanitizer('standard')
        validator = PodcastSecurityValidator()

        # 隐私净化测试
        test_text = "联系张三 zhangsan@email.com 13800138000"
        result = sanitizer.sanitize(test_text, user_id=1, context="test")
        assert "[EMAIL_REDACTED]" in result
        assert "[PHONE_REDACTED]" in result

        # XXE防护测试
        invalid_xml = '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
        valid, error = validator.validate_rss_xml(invalid_xml)
        assert valid == False

        print("   [PASS] Security module OK")
        return True
    except Exception as e:
        print(f"   [FAIL] Security: {e}")
        return False

# 测试2: Redis配置
def test_redis():
    print("TEST: Redis configuration...")
    try:
        from app.core.redis import PodcastRedis
        from app.core.config import settings

        print(f"   Redis URL: {settings.REDIS_URL}")
        print("   [PASS] Redis OK")
        return True
    except Exception as e:
        print(f"   [FAIL] Redis: {e}")
        return False

# 测试3: 数据库模型
def test_models():
    print("TEST: Database models...")
    try:
        from app.core.database import Base
        from app.domains.podcast.models import PodcastEpisode, PodcastPlaybackState

        # 检查模型定义
        assert hasattr(PodcastEpisode, 'audio_url')
        assert hasattr(PodcastPlaybackState, 'current_position')

        print("   [PASS] Models OK")
        return True
    except Exception as e:
        print(f"   [FAIL] Models: {e}")
        return False

# 测试4: 服务类导入
def test_services():
    print("TEST: Services layer...")
    try:
        from app.domains.podcast.services import PodcastService
        from app.domains.podcast.repositories import PodcastRepository

        print("   [PASS] Services OK")
        return True
    except Exception as e:
        print(f"   [FAIL] Services: {e}")
        return False

# 测试5: API路由定义
def test_api():
    print("TEST: API routing...")
    try:
        from app.domains.podcast.api.routes import router
        from fastapi import APIRouter

        assert isinstance(router, APIRouter)
        assert router.prefix == "/podcasts"

        print("   [PASS] API OK")
        return True
    except Exception as e:
        print(f"   [FAIL] API: {e}")
        return False

async def test_full_workflow():
    """完整工作流集成测试"""
    print("\nTEST: Full workflow integration...")

    try:
        from app.core.database import engine
        from sqlalchemy import inspect
        from sqlalchemy.ext.asyncio import AsyncSession

        # 检查数据库连接
        async with engine.connect() as conn:
            result = await conn.execute(await conn.execute("SELECT 1"))
            assert result.scalar() == 1

        # 检查表结构
        async with AsyncSession(engine) as session:
            inspector = inspect(engine)
            tables = inspector.get_table_names()

            if 'podcast_episodes' in tables:
                print("   [PASS] podcast_episodes table exists")
            else:
                print("   [INFO] podcast_episodes table missing (run migration first)")

            if 'podcast_playback_states' in tables:
                print("   [PASS] podcast_playback_states table exists")
            else:
                print("   [INFO] podcast_playback_states table missing")

        print("   [PASS] Workflow base OK")
        return True

    except Exception as e:
        print(f"   [FAIL] Workflow: {e}")
        return False

def main():
    """运行所有测试"""
    print("=" * 60)
    print("PODCAST FEATURE INTEGRITY CHECK")
    print("=" * 60)

    results = []

    # 同步测试
    results.append(test_security())
    results.append(test_redis())
    results.append(test_models())
    results.append(test_services())
    results.append(test_api())

    # 异步测试
    results.append(asyncio.run(test_full_workflow()))

    print("\n" + "=" * 60)
    passed = sum(results)
    total = len(results)

    if passed == total:
        print(f"\n[PASS] ALL ({passed}/{total}) ✓")
        print("\nNext steps:")
        print("1. python database_migration.py")
        print("2. uvicorn app.main:app --reload")
        print("3. http://localhost:8000/docs")
        return 0
    else:
        print(f"\n[PARTIAL] {passed}/{total}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
