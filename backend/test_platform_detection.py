"""
Quick test script for platform detection
"""

from app.domains.podcast.integration.platform_detector import (
    PlatformDetector,
    PodcastPlatform,
)


# Test cases
test_urls = [
    ("https://www.xiaoyuzhou.fm/podcast/123.xml", PodcastPlatform.XIAOYUZHOU),
    ("https://www.ximalaya.com/album/12345.xml", PodcastPlatform.XIMALAYA),
    ("https://feeds.megaphone.fm/podcast.xml", PodcastPlatform.GENERIC),
]

print("Testing Platform Detection:")
print("-" * 50)

for url, expected in test_urls:
    detected = PlatformDetector.detect_platform(url)
    status = "PASS" if detected == expected else "FAIL"
    print(f"[{status}] {url}")
    print(f"  Expected: {expected}, Got: {detected}")
    print()

# Test Ximalaya URL validation
print("\nTesting Ximalaya URL Validation:")
print("-" * 50)

ximalaya_urls = [
    ("https://www.ximalaya.com/album/12345.xml", True),
    ("https://ximalaya.com/album/67890.xml", True),
    ("https://www.ximalaya.com/invalid", False),
]

for url, should_be_valid in ximalaya_urls:
    valid, error = PlatformDetector.validate_platform_url(url, PodcastPlatform.XIMALAYA)
    status = "PASS" if valid == should_be_valid else "FAIL"
    print(f"[{status}] {url}")
    print(f"  Valid: {valid}, Error: {error}")
    print()

print("Test completed!")
