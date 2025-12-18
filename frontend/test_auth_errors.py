import requests
import json

def test_password_validation():
    base_url = "http://localhost:8000/api/v1"

    print("Testing password validation...\n")

    # Test cases
    test_cases = [
        {
            "email": "test1@example.com",
            "password": "A1234567",  # Missing lowercase
            "username": "test1",
            "full_name": "Test 1",
            "expected_error": "lowercase"
        },
        {
            "email": "test2@example.com",
            "password": "a1234567",  # Missing uppercase
            "username": "test2",
            "full_name": "Test 2",
            "expected_error": "uppercase"
        },
        {
            "email": "test3@example.com",
            "password": "Aa12345",   # Too short
            "username": "test3",
            "full_name": "Test 3",
            "expected_error": "8 characters"
        },
        {
            "email": "test4@example.com",
            "password": "Password",  # Missing number
            "username": "test4",
            "full_name": "Test 4",
            "expected_error": "number"
        },
        {
            "email": "test5@example.com",
            "password": "Aa12345678",  # Valid password
            "username": "test5",
            "full_name": "Test 5",
            "expected_error": None
        }
    ]

    for i, test_case in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i} ---")
        print(f"Password: {test_case['password']}")

        response = requests.post(
            f"{base_url}/auth/register",
            json={
                "email": test_case["email"],
                "password": test_case["password"],
                "username": test_case["username"],
                "full_name": test_case["full_name"]
            }
        )

        if response.status_code == 422:
            error_data = response.json()
            print(f"❌ Validation failed")
            print(f"Error: {error_data['detail']}")
            if 'errors' in error_data:
                for error in error_data['errors']:
                    print(f"  - {error['field']}: {error['message']}")
        elif response.status_code == 201:
            print(f"✅ Registration successful!")
            print(f"User ID: {response.json()['id']}")
        elif response.status_code == 409:
            print(f"⚠️  Email already registered")
        else:
            print(f"❓ Unexpected status code: {response.status_code}")
            print(f"Response: {response.text}")

if __name__ == "__main__":
    test_password_validation()