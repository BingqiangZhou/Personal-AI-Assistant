# Ximalaya RSS Feed Support Implementation

## Summary

This implementation adds backend support for Ximalaya (喜马拉雅) RSS feed parsing in the podcast subscription system, alongside the existing support for other podcast platforms.

## Changes Made

### 1. Platform Detection Module (`app/integration/podcast/platform_detector.py`)

**New file** that provides:
- `PodcastPlatform` class with platform identifiers (xiaoyuzhou, ximalaya, generic)
- `PlatformDetector` class with methods:
  - `detect_platform(feed_url)`: Detects platform from RSS feed URL
  - `validate_platform_url(feed_url, platform)`: Validates URL format for specific platforms
  - `_validate_ximalaya_url(url)`: Validates Ximalaya RSS URL format (expects: `https://www.ximalaya.com/album/{album_id}.xml`)

### 2. RSS Parser Updates (`app/integration/podcast/secure_rss_parser.py`)

**Modified** to:
- Import `PlatformDetector`
- Add `platform` field to `PodcastFeed` dataclass
- Detect platform in `fetch_and_parse_feed()` method
- Pass platform through parsing pipeline
- Include platform in returned feed data

### 3. Service Layer Updates (`app/domains/podcast/services.py`)

**Modified** to:
- Store platform information in subscription metadata when creating subscriptions
- Store platform information when reparsing subscriptions
- Platform is stored in the `config` JSON field of the `subscriptions` table

## Database Schema

No migration required. Platform information is stored in the existing `subscriptions.config` JSON field:

```json
{
  "author": "...",
  "language": "...",
  "categories": [...],
  "platform": "ximalaya"  // NEW FIELD
}
```

## Supported Platforms

1. **Xiaoyuzhou** (小宇宙)
   - URL patterns: `xiaoyuzhou.fm`, `xiaoyuzhoufm.com`
   - Platform identifier: `"xiaoyuzhou"`

2. **Ximalaya** (喜马拉雅)
   - URL patterns: `ximalaya.com`, `xmcdn.com`
   - Expected format: `https://www.ximalaya.com/album/{album_id}.xml`
   - Platform identifier: `"ximalaya"`

3. **Generic**
   - Any other RSS feed URL
   - Platform identifier: `"generic"`

## Testing

### Unit Test (Completed ✓)

```bash
cd backend
python test_platform_detection.py
```

**Results:**
- ✓ Xiaoyuzhou URL detection
- ✓ Ximalaya URL detection
- ✓ Generic URL fallback
- ✓ Ximalaya URL validation

### Integration Test (Manual)

1. Start Docker containers:
```bash
cd docker
docker-compose -f docker-compose.podcast.yml up -d
```

2. Create a test user and get authentication token

3. Test Ximalaya subscription:
```bash
curl -X POST http://localhost:8000/api/v1/podcasts/subscriptions \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "feed_url": "https://www.ximalaya.com/album/12345.xml",
    "custom_name": "Test Ximalaya Podcast"
  }'
```

4. Verify platform is stored:
```bash
curl http://localhost:8000/api/v1/podcasts/subscriptions \
  -H "Authorization: Bearer <token>"
```

Check that the response includes `"platform": "ximalaya"` in the subscription metadata.

## Error Handling

- Invalid Ximalaya URLs are rejected with a descriptive error message
- Invalid RSS feed URLs are caught by existing security validation
- Platform detection failures fall back to "generic" platform
- All existing error handling remains intact

## Backward Compatibility

- Existing subscriptions without platform information continue to work
- Platform field is optional in metadata
- No breaking changes to API or database schema
- Existing Xiaoyuzhou and generic RSS feeds continue to work as before

## Code Quality

- ✓ Syntax validation passed for all modified files
- ✓ Minimal code changes (only added necessary functionality)
- ✓ Reused existing RSS parsing infrastructure
- ✓ Followed existing code patterns and conventions
- ✓ Added proper logging for platform detection

## Files Modified

1. `backend/app/integration/podcast/platform_detector.py` (NEW)
2. `backend/app/integration/podcast/secure_rss_parser.py` (MODIFIED)
3. `backend/app/domains/podcast/services.py` (MODIFIED)
4. `backend/test_platform_detection.py` (NEW - test script)

## Next Steps

To fully test the implementation:

1. Run the full test suite:
```bash
cd docker
docker-compose -f docker-compose.podcast.yml exec backend pytest app/domains/podcast/tests/ -v
```

2. Test with a real Ximalaya RSS feed URL

3. Verify the platform information is correctly displayed in the frontend

4. Add frontend support to display platform badges/icons (optional enhancement)
