#!/bin/bash

# Test Authentication Endpoints with curl
BASE_URL="http://localhost:8000"
API_V1="/api/v1"

echo "Testing Authentication Endpoints"
echo "================================"

# 1. Health Check
echo -e "\n1. Health Check:"
curl -s "$BASE_URL/health" | jq .

# 2. Register User
echo -e "\n2. Register User:"
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL$API_V1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "testpassword123",
    "username": "testuser",
    "full_name": "Test User"
  }')
echo "$REGISTER_RESPONSE" | jq .

# 3. Login
echo -e "\n3. Login:"
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL$API_V1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email_or_username": "test@example.com",
    "password": "testpassword123"
  }')
echo "$LOGIN_RESPONSE" | jq .

# Extract tokens
ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.refresh_token')

echo -e "\nAccess Token: ${ACCESS_TOKEN:0:50}..."

# 4. Get Current User Info
echo -e "\n4. Get Current User Info:"
curl -s -X GET "$BASE_URL$API_V1/auth/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

# 5. Refresh Token
echo -e "\n5. Refresh Token:"
REFRESH_RESPONSE=$(curl -s -X POST "$BASE_URL$API_V1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}")
echo "$REFRESH_RESPONSE" | jq .

# Update access token if refresh succeeded
NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.access_token')
if [ "$NEW_ACCESS_TOKEN" != "null" ] && [ "$NEW_ACCESS_TOKEN" != "" ]; then
    ACCESS_TOKEN="$NEW_ACCESS_TOKEN"
    echo -e "\nUpdated Access Token: ${ACCESS_TOKEN:0:50}..."
fi

# 6. Logout
echo -e "\n6. Logout:"
curl -s -X POST "$BASE_URL$API_V1/auth/logout" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}" | jq .

# 7. Try to access protected endpoint after logout
echo -e "\n7. Access Protected Endpoint After Logout:"
curl -s -X GET "$BASE_URL$API_V1/auth/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

echo -e "\n================================"
echo "Authentication Tests Complete!"
echo "================================"