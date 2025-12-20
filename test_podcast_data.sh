#!/bin/bash

# 首先注册一个测试用户
echo "注册测试用户..."
REGISTER_RESPONSE=$(curl -s -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "Test123456!",
    "username": "testuser"
  }')

echo "注册响应: $REGISTER_RESPONSE"

# 登录获取token
echo ""
echo "登录获取token..."
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "Test123456!"
  }')

TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.access_token')
echo "Token: $TOKEN"

# 添加播客订阅
echo ""
echo "添加播客订阅..."
SUBSCRIBE_RESPONSE=$(curl -s -X POST http://localhost:8000/api/v1/podcasts/subscriptions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "feed_url": "https://feeds.simplecast.com/your_daily_fix"
  }')

echo "订阅响应: $SUBSCRIBE_RESPONSE"

# 获取Feed列表
echo ""
echo "获取Feed..."
curl -s -X GET http://localhost:8000/api/v1/podcasts/episodes/feed \
  -H "Authorization: Bearer $TOKEN" | jq '.'