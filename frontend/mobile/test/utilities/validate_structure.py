#!/usr/bin/env python3
"""
Flutter Mobile App Structure Validation Script
Validates all required files exist and dependencies are properly configured
"""

import os
import sys
import json
from pathlib import Path

class FlutterStructureValidator:
    def __init__(self, project_root):
        self.project_root = Path(project_root)
        self.errors = []
        self.warnings = []

    def log_error(self, msg):
        print(f"[ERROR] {msg}")
        self.errors.append(msg)

    def log_warning(self, msg):
        print(f"[WARNING] {msg}")
        self.warnings.append(msg)

    def log_success(self, msg):
        print(f"[PASS] {msg}")

    def validate_pubspec_exists(self):
        """Validate pubspec.yaml exists and has required dependencies"""
        pubspec_path = self.project_root / "pubspec.yaml"
        if not pubspec_path.exists():
            self.log_error("pubspec.yaml not found")
            return False

        self.log_success("pubspec.yaml exists")

        try:
            with open(pubspec_path, 'r', encoding='utf-8') as f:
                content = f.read()
            required_packages = [
                "flutter_riverpod",
                "go_router",
                "dio",
                "hive",
                "flutter_secure_storage",
                "intl"
            ]

            missing = []
            for package in required_packages:
                if package.lower() not in content.lower():
                    missing.append(package)

            if missing:
                self.log_warning(f"Missing recommended packages: {', '.join(missing)}")
            else:
                self.log_success("All required packages declared")

        except Exception as e:
            self.log_error(f"Could not read pubspec.yaml: {e}")
            return False

        return True

    def validate_directory_structure(self):
        """Validate core project structure"""
        required_dirs = [
            "lib",
            "lib/core",
            "lib/shared",
            "lib/features",
            "lib/models",
            "lib/services",
            "lib/providers",
            "lib/routers",
            "lib/screens",
            "test",
            "test/services",
            "test/providers",
            "test/routers",
            "test/integration"
        ]

        for dir_name in required_dirs:
            dir_path = self.project_root / dir_name
            if not dir_path.exists():
                self.log_error(f"Required directory missing: {dir_name}")
            else:
                self.log_success(f"Directory exists: {dir_name}")

    def validate_core_files(self):
        """Validate essential core files"""
        core_files = [
            "lib/main.dart",
            "lib/core/constants.dart",
            "lib/core/api_config.dart",
            "lib/services/dio_client.dart",
            "lib/services/auth_service.dart",
            "lib/services/assistant_service.dart",
            "lib/services/knowledge_service.dart",
            "lib/services/podcast_service.dart",
            "lib/providers/auth_provider.dart",
            "lib/providers/conversation_provider.dart",
            "lib/routers/app_router.dart",
            "lib/models/token.dart",
            "lib/models/user.dart",
            "lib/models/conversation.dart",
            "lib/models/knowledge.dart",
            "lib/models/podcast.dart",
            "test/utilities/run_all_tests.bat",
            "test/utilities/run_all_tests.sh",
            "test/utilities/validate_structure.py"
        ]

        for file_path in core_files:
            full_path = self.project_root / file_path
            if not full_path.exists():
                self.log_error(f"Missing core file: {file_path}")
            else:
                self.log_success(f"File exists: {file_path}")

    def validate_test_files(self):
        """Validate comprehensive test coverage"""
        test_files = [
            "test/widget_test.dart",
            "test/services/auth_service_test.dart",
            "test/services/assistant_service_test.dart",
            "test/services/knowledge_service_test.dart",
            "test/services/podcast_service_test.dart",
            "test/providers/auth_provider_test.dart",
            "test/routers/router_test.dart",
            "test/integration/api_integration_test.dart",
            "test/integration/user_flow_test.dart"
        ]

        for test_file in test_files:
            full_path = self.project_root / test_file
            if not full_path.exists():
                self.log_error(f"Missing test file: {test_file}")
            else:
                self.log_success(f"Test file exists: {test_file}")

    def validate_main_screen_files(self):
        """Validate main screen implementations"""
        screens = [
            "lib/screens/splash/splash_screen.dart",
            "lib/screens/auth/login_screen.dart",
            "lib/screens/auth/register_screen.dart",
            "lib/screens/dashboard/dashboard_screen.dart",
            "lib/screens/chat/chat_screen.dart",
            "lib/screens/chat/conversation_list_screen.dart",
            "lib/screens/knowledge/knowledge_list_screen.dart",
            "lib/screens/knowledge/knowledge_base_screen.dart",
            "lib/screens/podcast/podcast_subscription_screen.dart",
            "lib/screens/podcast/podcast_player_screen.dart"
        ]

        for screen in screens:
            full_path = self.project_root / screen
            if not full_path.exists():
                self.log_warning(f"Screen not fully implemented: {screen}")
            else:
                content = full_path.read_text(encoding='utf-8')
                # Check if it's just a placeholder
                if "开发中" in content or "function that returns a widget" in content:
                    self.log_warning(f"Screen not fully implemented (placeholder): {screen}")
                else:
                    self.log_success(f"Screen implemented: {screen}")

    def validate_api_endpoints(self):
        """Check API endpoint references in Flutter code"""
        # Services use relative paths that combine with baseUrl
        endpoint_patterns = [
            '"/auth/register"',
            '"/auth/login"',
            '"/auth/refresh"',
            '"/auth/logout"',
            '"/auth/me"',
            '"/chat"',
            '"/conversations"',
            '"/knowledge/bases',
            '"/podcasts/subscription',
            '"/podcasts/episodes',
            '"/subscriptions'
        ]

        print("\nAPI Endpoints Validation:")
        patterns_found = []

        # Search in services directory
        services_dir = self.project_root / "lib" / "services"
        if services_dir.exists():
            for service_file in services_dir.glob("*.dart"):
                content = service_file.read_text(encoding='utf-8')
                for pattern in endpoint_patterns:
                    if pattern in content:
                        patterns_found.append(pattern)

        # Check critical endpoints
        auth_endpoints = ['"/auth/register"', '"/auth/login"', '"/auth/me"']
        assistant_endpoints = ['"/chat"', '"/conversations"']

        for pattern in auth_endpoints:
            if pattern in patterns_found:
                self.log_success(f"Auth endpoint: {pattern}")
            else:
                self.log_error(f"Critical auth endpoint missing: {pattern}")

        for pattern in assistant_endpoints:
            if pattern in patterns_found:
                self.log_success(f"Assistant endpoint: {pattern}")
            else:
                self.log_warning(f"Assistant endpoint missing: {pattern}")

        # Check other endpoints
        other_endpoints = [
            '"/knowledge/bases', '"/podcasts/subscription',
            '"/podcasts/episodes', '"/subscriptions'
        ]

        for pattern in other_endpoints:
            found = any(pattern in pf for pf in patterns_found)
            if found:
                self.log_success(f"Endpoint: {pattern}")
            else:
                self.log_warning(f"Not yet implemented: {pattern}")

    def check_duplicate_code(self):
        """Check for common issues like duplicate code"""
        # Check for planned but not yet complete features
        incomplete_features = [
            "Todo: Implement user registration logic",
            "TODO: Implement login logic",
            "Function that returns a widget",
            "Slot for",
            "TODO: Implement"
        ]

        print("\nCompleteness Check:")
        all_files = list(self.project_root.rglob("*.dart"))
        incomplete_count = 0

        for file_path in all_files:
            try:
                content = file_path.read_text(encoding='utf-8')
                for pattern in incomplete_features:
                    if pattern in content:
                        incomplete_count += 1
                        relative_path = file_path.relative_to(self.project_root)
                        self.log_warning(f"Incomplete: {relative_path}")
                        break
            except:
                pass

        if incomplete_count == 0:
            self.log_success("No obvious incomplete features found")
        else:
            self.log_warning(f"Found {incomplete_count} incomplete features")

    def run_validation(self):
        """Run complete validation"""
        print("=" * 60)
        print("Flutter Mobile App Structure Validation")
        print("=" * 60)
        print()

        self.validate_pubspec_exists()
        print()
        self.validate_directory_structure()
        print()
        self.validate_core_files()
        print()
        self.validate_test_files()
        print()
        self.validate_main_screen_files()
        print()
        self.validate_api_endpoints()
        print()
        self.check_duplicate_code()

        print("\n" + "=" * 60)
        print("VALIDATION SUMMARY")
        print("=" * 60)
        print(f"Errors: {len(self.errors)}")
        print(f"Warnings: {len(self.warnings)}")

        if len(self.errors) == 0:
            print("\n[PASS] Structure validation PASSED!")
            return True
        else:
            print("\n[FAIL] Structure validation FAILED - Fix errors")
            return False

if __name__ == "__main__":
    # Determine project root (test/utilities/validate_structure.py -> frontend/mobile)
    script_path = Path(__file__).resolve()
    project_root = script_path.parent.parent.parent

    validator = FlutterStructureValidator(project_root)
    success = validator.run_validation()
    sys.exit(0 if success else 1)
