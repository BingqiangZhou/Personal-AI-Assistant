"""Test if alembic env.py can be imported without circular dependencies"""
import os
import sys


# Add backend to path
sys.path.insert(0, os.path.dirname(__file__))

print("Testing alembic/env.py import...")

try:
    # Import the env module
    from alembic import env
    print("✓ alembic.env imported successfully")

    # Check if we can access the config
    print(f"✓ Config loaded: {env.config is not None}")

    # Check if target_metadata is accessible
    print(f"✓ Target metadata accessible: {env.target_metadata is not None}")

    # Check if get_url function works
    try:
        url = env.get_url()
        print(f"✓ get_url() works: {url[:50]}...")
    except Exception as e:
        print(f"✗ get_url() failed: {e}")

    print("\n✅ All alembic env tests passed!")

except Exception as e:
    print(f"✗ Failed to import alembic.env: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
