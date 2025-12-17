#!/usr/bin/env python3
import sys
import io
import ast
import pathlib

# Set UTF-8 output
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def test_stage2():
    print('=== Stage 2: Database Integrity & Security Validation ===')
    print('Performing structural validation without external dependencies...')

    all_pass = True

    # Check 1: Models validation
    try:
        model_file = pathlib.Path('app/domains/podcast/models.py')
        with open(model_file, 'r', encoding='utf-8') as f:
            content = f.read()
        ast.parse(content)
        print('[PASS] Podcast models syntax validation')
    except Exception as e:
        print(f'[FAIL] Model validation: {e}')
        all_pass = False

    # Check 2: Migration script
    try:
        migration_file = pathlib.Path('database_migration.py')
        if migration_file.exists():
            with open(migration_file, 'r', encoding='utf-8') as f:
                content = f.read()
            ast.parse(content)
            print('[PASS] Migration script syntax valid')
        else:
            print('[WARN] Migration script not found')
            all_pass = False
    except Exception as e:
        print(f'[FAIL] Migration script: {e}')
        all_pass = False

    # Check 3: Critical security - XXE protection
    try:
        from app.integration.podcast.security import PodcastSecurityValidator
        validator = PodcastSecurityValidator()

        malicious_xml = '''<?xml version="1.0"?>
        <!DOCTYPE data [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <data>&xxe;</data>'''

        is_valid, error = validator.validate_rss_xml(malicious_xml)
        if not is_valid:
            print('[PASS] XXE protection blocked malicious content')
        else:
            print('[CRITICAL] XXE protection FAILED - VULNERABILITY!')
            all_pass = False
    except Exception as e:
        print(f'[FAIL] XXE test error: {e}')
        all_pass = False

    # Check 4: Privacy filtering
    try:
        from app.core.llm_privacy import ContentSanitizer

        sanitizer = ContentSanitizer('standard')
        test_input = '联系张三 zhangsan@company.com 13800138000'
        result = sanitizer.sanitize(test_input, 1, 'test')

        email_redacted = '[EMAIL_REDACTED]' in result or 'REDACTED' in result
        phone_redacted = '[PHONE_REDACTED]' in result or 'REDACTED' in result

        if email_redacted and phone_redacted:
            print(f'[PASS] Privacy filtering: "{test_input}" -> "{result}"')
        else:
            print(f'[FAIL] Privacy filtering incomplete: "{result}"')
            all_pass = False
    except Exception as e:
        print(f'[FAIL] Privacy filter: {e}')
        all_pass = False

    # Check 5: Service layer imports
    try:
        from app.domains.podcast.services import PodcastService
        from app.domains.podcast.repositories import PodcastRepository
        print('[PASS] Podcast service layers importable')
    except Exception as e:
        print(f'[FAIL] Service imports: {e}')
        all_pass = False

    # Check 6: Secure RSS parser
    try:
        from app.integration.podcast.secure_rss_parser import SecureRSSParser, PodcastFeed
        print('[PASS] Secure RSS parser components')
    except Exception as e:
        print(f'[FAIL] RSS parser: {e}')
        all_pass = False

    if all_pass:
        print('\n[SUCCESS] Stage 2 Complete')
        return True
    else:
        print('\n[FAILED] Stage 2 has issues')
        return False

if __name__ == '__main__':
    success = test_stage2()
    sys.exit(0 if success else 1)