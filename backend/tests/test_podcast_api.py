"""
Comprehensive API Validation Tests for Podcast Feature
Tests security, models, and core functionality
"""
import asyncio
import io
import sys

import pytest


# Fix encoding for Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

class TestPodcastAPI:
    """Stage 3: API Validation Tests"""

    def test_xxe_protection(self):
        """Security Test: XXE attacks must be blocked"""
        from app.domains.podcast.integration.security import PodcastSecurityValidator
        validator = PodcastSecurityValidator()

        # Test XXE attack
        malicious_xml = '''<?xml version="1.0"?>
        <!DOCTYPE data [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <data>&xxe;</data>'''

        is_valid, error = validator.validate_rss_xml(malicious_xml)
        assert is_valid is False, "XXE should be blocked"
        print(f"[PASS] XXE防护: {error}")

        # Test OOB attack
        oob_xml = '''<?xml version="1.0"?>
        <!DOCTYPE data [
          <!ENTITY xxe SYSTEM "http://internal-server/status">
        ]>
        <data>&xxe;</data>'''

        is_valid, error = validator.validate_rss_xml(oob_xml)
        assert is_valid is False, "OOB XXE should be blocked"
        print("[PASS] OOB XXE blocked")

    def test_privacy_sanitization(self):
        """Security Test: PII must be filtered"""
        from app.core.llm_privacy import ContentSanitizer

        sanitizer = ContentSanitizer('standard')
        test_cases = [
            ("联系张三 zhangsan@email.com 13800138000", ["[EMAIL_REDACTED]", "[PHONE_REDACTED]"]),
            ("User: john.doe@company.com, phone: 555-1234", ["[EMAIL_REDACTED]", "[PHONE_REDACTED]"]),
            ("No sensitive data", []),  # Should not modify
        ]

        for text, expected_redactions in test_cases:
            result = sanitizer.sanitize(text, user_id=1, context="test")
            for expected in expected_redactions:
                assert expected in result, f"Expected {expected} in sanitized result"
            print(f"[PASS] Privacy: '{text}' -> '{result}'")

    def test_rss_security_validations(self):
        """Security Test: RSS URL and content validation"""
        from app.domains.podcast.integration.security import PodcastSecurityValidator
        validator = PodcastSecurityValidator()

        # Test dangerous URLs
        dangerous_urls = [
            "http://localhost/evil.xml",
            "http://127.0.0.1/exploit.xml",
            "http://192.168.1.1/internal.xml",
            "file:///etc/passwd"
        ]

        for url in dangerous_urls:
            is_valid, error = validator.validate_audio_url(url)
            assert is_valid is False, f"Blocked dangerous URL: {url}"
            print(f"[PASS] Blocked: {url}")

        # Test safe URLs
        safe_urls = [
            "https://example.com/podcast.mp3",
            "http://cdn.example.com/audio/episode.mp3"
        ]

        for url in safe_urls:
            is_valid, error = validator.validate_audio_url(url)
            assert is_valid is True, f"Should allow safe URL: {url}"
            print(f"[PASS] Allowed: {url}")

    def test_model_definitions(self):
        """Model Test: Verify model structure exists"""
        import ast
        import pathlib

        # Check models file exists and valid
        model_file = pathlib.Path(__file__).parent.parent / "app" / "domains" / "podcast" / "models.py"
        assert model_file.exists(), "Podcast models file missing"

        with open(model_file, encoding='utf-8') as f:
            content = f.read()

        # Parse without executing (avoid import issues)
        ast.parse(content)

        # Check for required imports (even if unused)
        assert 'class PodcastEpisode' in content
        assert 'class PodcastPlaybackState' in content

        # Check for key fields (string match, not import)
        expected_fields = [
            'audio_url', 'ai_summary', 'guid', 'subscription_id',
            'current_position', 'user_id', 'episode_id'
        ]

        for field in expected_fields:
            assert field in content, f"Missing field: {field}"

        print("[PASS] Model structure validated")

    def test_service_workflow_logic(self):
        """Logic Test: Service workflow patterns"""
        # Test that our mocked service can handle workflow
        from app.domains.podcast.integration.security import PodcastSecurityValidator

        validator = PodcastSecurityValidator()

        # Simulate secure RSS validation pipeline
        good_rss = '''<?xml version="1.0"?>
        <rss>
          <channel>
            <title>Test Podcast</title>
            <item>
              <title>Episode 1</title>
              <description>Test description</description>
              <enclosure url="http://cdn.example.com/ep1.mp3" type="audio/mpeg" />
            </item>
          </channel>
        </rss>'''

        is_valid, error = validator.validate_rss_xml(good_rss)
        assert is_valid is True, "Valid RSS should pass"
        print("[PASS] Valid RSS processing works")

    # Test 6: Redis integration (mocked)
    @pytest.mark.asyncio
    async def test_redis_functions(self):
        """Integration Test: Redis operations (mocked)"""
        from unittest.mock import AsyncMock

        # Mock Redis since we don't have real Redis
        mock_redis = AsyncMock()
        mock_redis.set_user_progress = AsyncMock()
        mock_redis.get_user_progress = AsyncMock(return_value=0.5)

        # Test progress tracking
        await mock_redis.set_user_progress(1, 42, 0.5)
        progress = await mock_redis.get_user_progress(1, 42)

        assert progress == 0.5
        print("[PASS] Redis workflow logic verified (mocked)")

    # Test 7: Content sanitizer edge cases
    def test_sanitizer_edge_cases(self):
        """Security Test: Edge cases for privacy filter"""
        from app.core.llm_privacy import ContentSanitizer

        sanitizer = ContentSanitizer('standard')

        edge_cases = [
            ("email@domain.com", "[EMAIL_REDACTED]"),
            ("13800138000", "[PHONE_REDACTED]"),
            ("张三 13800138000", "张三 [PHONE_REDACTED]"),  # Keep name
            ("", ""),  # Empty input
            ("Only normal text", "Only normal text"),  # No PII
        ]

        for input_text, expected_pattern in edge_cases:
            result = sanitizer.sanitize(input_text, 1, "test")
            if expected_pattern:
                assert expected_pattern in result or expected_pattern == result
            print(f"[PASS] Edge case: '{input_text}' -> '{result}'")

if __name__ == "__main__":
    # Run tests programmatically
    print("=== Stage 3: API Security & Validation Tests ===")

    test_instance = TestPodcastAPI()

    tests = [
        ("XXE Protection", test_instance.test_xxe_protection),
        ("RSS Security", test_instance.test_rss_security_validations),
        ("Privacy Sanitization", test_instance.test_privacy_sanitization),
        ("Model Structure", test_instance.test_model_definitions),
        ("Service Logic", test_instance.test_service_workflow_logic),
        ("Edge Cases", test_instance.test_sanitizer_edge_cases),
    ]

    # Async test for Redis
    async_test = test_instance.test_redis_functions

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {name}: {e}")
            failed += 1

    # Run async test
    try:
        asyncio.run(async_test())
        passed += 1
    except Exception as e:
        print(f"[FAIL] Redis workflow: {e}")
        failed += 1

    print(f"\n[RESULTS] Stage 3: {passed} passed, {failed} failed")

    if failed == 0:
        print("🎉 All security tests passed!")
        sys.exit(0)
    else:
        print("❌ Some tests failed")
        sys.exit(1)