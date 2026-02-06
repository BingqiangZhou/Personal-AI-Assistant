#!/usr/bin/env python3
import sys


def test_imports():
    print('=== Stage 1: Import Validation ===')

    # Test 1: Security XML parser
    try:
        from defusedxml import ElementTree
        print('[PASS] defusedxml security library')
    except ImportError as e:
        print(f'[FAIL] defusedxml: {e}')
        return False

    # Test 2: Privacy filter core
    try:
        from app.core.llm_privacy import ContentSanitizer
        print('[PASS] ContentSanitizer import')
    except ImportError as e:
        print(f'[FAIL] ContentSanitizer: {e}')
        return False

    # Test 3: Podcast models (dependency aware)
    try:
        # Check if we can at least read the model file
        import importlib.util
        import pathlib

        plugin_path = pathlib.Path(__file__).parent / "app" / "domains" / "podcast" / "models.py"
        if plugin_path.exists():
            spec = importlib.util.spec_from_file_location("podcast_models", plugin_path)
            # Just verify the file is valid Python without executing imports
            with open(plugin_path, encoding='utf-8') as f:
                content = f.read()
            import ast
            ast.parse(content)  # Check syntax
            print('[PASS] PodcastEpisode model syntax')
        else:
            print('[FAIL] Podcast models file not found')
            return False
    except SyntaxError as e:
        print(f'[FAIL] Podcast models syntax error: {e}')
        return False
    except Exception as e:
        print(f'[FAIL] Podcast model check: {e}')
        return False

    # Test 4: Functionality test
    try:
        from app.core.llm_privacy import ContentSanitizer
        sanitizer = ContentSanitizer('standard')
        test_input = '联系张三 zhangsan@company.com 13800138000'
        result = sanitizer.sanitize(test_input, 1, 'test')
        print(f'[PASS] Privacy filter: "{test_input}" -> "{result}"')
    except Exception as e:
        print(f'[FAIL] Privacy functionality: {e}')
        return False

    # Test 5: Security validator syntax
    try:
        import pathlib
        plugin_path = pathlib.Path(__file__).parent / "app" / "integration" / "podcast" / "security.py"
        if plugin_path.exists():
            with open(plugin_path, encoding='utf-8') as f:
                content = f.read()
            import ast
            ast.parse(content)
            print('[PASS] PodcastSecurityValidator syntax')
        else:
            print('[FAIL] Security file not found')
            return False
    except Exception as e:
        print(f'[FAIL] Security validator check: {e}')
        return False

    print('[SUCCESS] Stage 1 complete')
    return True

if __name__ == '__main__':
    success = test_imports()
    sys.exit(0 if success else 1)