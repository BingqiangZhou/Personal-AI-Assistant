#!/usr/bin/env python3
"""
Quick validation script - verifies key files and endpoints
"""
import os
from pathlib import Path

def verify():
    project_root = Path(__file__).resolve().parent.parent.parent
    errors = 0
    warnings = 0

    print("Flutter Mobile App - Quick Validation")
    print("=" * 50)

    # Check key files
    key_files = {
        "lib/main.dart": "Main application entry",
        "lib/services/auth_service.dart": "Authentication service",
        "lib/services/assistant_service.dart": "AI assistant service",
        "lib/services/knowledge_service.dart": "Knowledge service ",
        "lib/services/podcast_service.dart": "Podcast service",
        "lib/providers/auth_provider.dart": "Auth state management",
        "lib/providers/conversation_provider.dart": "Conversation state",
        "lib/routers/app_router.dart": "Navigation router",
        "lib/core/constants.dart": "API constants",
        "lib/core/api_config.dart": "API configuration",
    }

    print("\n1. Core Files Check:")
    for file_path, desc in key_files.items():
        full_path = project_root / file_path
        if full_path.exists():
            print(f"[OK] {desc}")
        else:
            print(f"[MISSING] {desc}")
            errors += 1

    # Check services for endpoints
    print("\n2. Endpoint Check (searching services):")
    services_dir = project_root / "lib" / "services"
    if services_dir.exists():
        # Patterns to find
        patterns = {
            "/auth/register": "Auth register",
            "/auth/login": "Auth login",
            "/auth/me": "Auth me",
            "/assistant/conversations": "Assistant conversations",
            "/assistant/chat": "Assistant chat",
            "/knowledge/bases": "Knowledge base",
            "/podcasts/subscription": "Podcast subscription",
            "/podcasts/episodes": "Podcast episodes",
        }

        for pattern, desc in patterns.items():
            # Search in dart files
            found = False
            for dart_file in services_dir.glob("*.dart"):
                content = dart_file.read_text(encoding='utf-8', errors='ignore')
                if pattern in content:
                    found = True
                    break

            if found:
                print(f"[OK] Endpoint: {desc} = {pattern}")
            else:
                print(f"[MISSING] Endpoint: {desc}")
                warnings += 1

    # Check test files
    print("\n3. Test Files Check:")
    test_files = [
        "test/widget_test.dart",
        "test/services/auth_service_test.dart",
        "test/services/assistant_service_test.dart",
        "test/services/knowledge_service_test.dart",
        "test/services/podcast_service_test.dart",
        "test/integration/api_integration_test.dart",
    ]

    for test_file in test_files:
        full_path = project_root / test_file
        if full_path.exists():
            print(f"[OK] {test_file}")
        else:
            print(f"[MISSING] {test_file}")
            errors += 1

    print("\n" + "=" * 50)
    print(f"Summary: {errors} errors, {warnings} warnings")

    if errors == 0:
        print("\n✅ STRUCTURE VALIDATION PASSED")
        return True
    else:
        print("\n❌ STRUCTURE VALIDATION FAILED")
        return False

if __name__ == "__main__":
    verify()
