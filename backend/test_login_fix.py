#!/usr/bin/env python3
"""Test script to verify login API works with both username and email_or_username fields."""

import requests
import json

BASE_URL = "http://localhost:8000"

def test_login_with_username():
    """Test login using username field."""
    print("\n=== Testing login with 'username' field ===")

    # First register a test user
    register_data = {
        "email": "testuser@example.com",
        "username": "testuser123",
        "password": "TestPassword123"
    }

    # Try to register (may fail if user already exists)
    register_response = requests.post(f"{BASE_URL}/api/v1/auth/register", json=register_data)
    if register_response.status_code == 201:
        print("✓ Test user registered successfully")
    elif register_response.status_code == 409:
        print("ℹ Test user already exists, proceeding with login test")
    else:
        print(f"⚠ Registration failed with status {register_response.status_code}: {register_response.text}")

    # Test login with username field
    login_with_username = {
        "username": "testuser123",
        "password": "TestPassword123"
    }

    login_response = requests.post(f"{BASE_URL}/api/v1/auth/login", json=login_with_username)

    if login_response.status_code == 200:
        print("✓ Login with 'username' field: SUCCESS")
        token_data = login_response.json()
        print(f"  - Access token received: {token_data.get('access_token')[:20]}...")
        return token_data
    else:
        print(f"✗ Login with 'username' field: FAILED")
        print(f"  Status: {login_response.status_code}")
        print(f"  Response: {login_response.text}")
        return None

def test_login_with_email_or_username():
    """Test login using email_or_username field."""
    print("\n=== Testing login with 'email_or_username' field ===")

    # Test login with email_or_username field using email
    login_with_email = {
        "email_or_username": "testuser@example.com",
        "password": "TestPassword123"
    }

    login_response = requests.post(f"{BASE_URL}/api/v1/auth/login", json=login_with_email)

    if login_response.status_code == 200:
        print("✓ Login with 'email_or_username' field (using email): SUCCESS")
        token_data = login_response.json()
        print(f"  - Access token received: {token_data.get('access_token')[:20]}...")
        return token_data
    else:
        print(f"✗ Login with 'email_or_username' field (using email): FAILED")
        print(f"  Status: {login_response.status_code}")
        print(f"  Response: {login_response.text}")
        return None

def test_login_with_both_fields():
    """Test login when both fields are provided (username should take priority)."""
    print("\n=== Testing login with both fields (username priority) ===")

    # Test login with both fields
    login_with_both = {
        "username": "testuser123",
        "email_or_username": "different@example.com",  # This should be ignored
        "password": "TestPassword123"
    }

    login_response = requests.post(f"{BASE_URL}/api/v1/auth/login", json=login_with_both)

    if login_response.status_code == 200:
        print("✓ Login with both fields (username priority): SUCCESS")
        token_data = login_response.json()
        print(f"  - Access token received: {token_data.get('access_token')[:20]}...")
        return token_data
    else:
        print(f"✗ Login with both fields (username priority): FAILED")
        print(f"  Status: {login_response.status_code}")
        print(f"  Response: {login_response.text}")
        return None

def test_invalid_login():
    """Test login with no identifier fields."""
    print("\n=== Testing login with no identifier (should fail) ===")

    login_invalid = {
        "password": "TestPassword123"
        # No username or email_or_username
    }

    login_response = requests.post(f"{BASE_URL}/api/v1/auth/login", json=login_invalid)

    if login_response.status_code == 422:  # Validation error
        print("✓ Login with no identifier: Correctly FAILED with validation error")
        print(f"  Status: {login_response.status_code}")
        return True
    else:
        print(f"✗ Login with no identifier: Unexpected response")
        print(f"  Status: {login_response.status_code}")
        print(f"  Response: {login_response.text}")
        return False

if __name__ == "__main__":
    print("Testing Login API Field Compatibility Fix")
    print("=" * 50)

    # Check if server is running
    try:
        health_response = requests.get(f"{BASE_URL}/docs")
        if health_response.status_code != 200:
            print("❌ Backend server is not running or not accessible")
            print("Please start the backend server first:")
            print("  cd backend && uv run uvicorn app.main:app --reload")
            exit(1)
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend server")
        print("Please start the backend server first:")
        print("  cd backend && uv run uvicorn app.main:app --reload")
        exit(1)

    print("✅ Backend server is running")

    # Run tests
    test_login_with_username()
    test_login_with_email_or_username()
    test_login_with_both_fields()
    test_invalid_login()

    print("\n" + "=" * 50)
    print("Test suite completed!")