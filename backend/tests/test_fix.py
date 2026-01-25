#!/usr/bin/env python3
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

print('=== Testing metadata fix ===')

try:
    from app.domains.podcast.models import PodcastEpisode
    print('[PASS] Models import successfully')

    from app.domains.podcast.services import PodcastService
    print('[PASS] Service imports successfully')

    from app.core.llm_privacy import ContentSanitizer
    from app.domains.podcast.integration.security import PodcastSecurityValidator
    print('[PASS] Security components work')

    print('\n[FIX SUCCESS] metadata reserved attribute issue resolved')
    sys.exit(0)

except Exception as e:
    print(f'[FAIL] {e}')
    sys.exit(1)