import requests
import json

# API基础URL
BASE_URL = "http://localhost:8000/api/v1"

# 创建会话
session = requests.Session()

def login_user():
    """登录测试用户"""
    print("登录测试用户...")
    response = session.post(f"{BASE_URL}/auth/login", json={
        "email": "test@example.com",
        "password": "Test123456!"
    })

    if response.status_code == 200:
        data = response.json()
        token = data.get("access_token")
        print(f"登录成功！")
        return token
    else:
        print(f"登录失败: {response.text}")
        return None

def create_subscription(token):
    """创建播客订阅"""
    print("\n创建播客订阅...")
    headers = {"Authorization": f"Bearer {token}"}

    # 尝试添加一个已知的播客
    subscription_data = {
        "feed_url": "https://feeds.simplecast.com/your_daily_fix"
    }

    response = session.post(
        f"{BASE_URL}/podcasts/subscriptions",
        json=subscription_data,
        headers=headers
    )

    if response.status_code == 201:
        data = response.json()
        print(f"订阅成功！订阅ID: {data.get('id')}")
        return data.get('id')
    else:
        print(f"订阅失败: {response.text}")
        return None

def get_feed_data(token):
    """获取Feed数据"""
    print("\n获取播客Feed...")
    headers = {"Authorization": f"Bearer {token}"}

    response = session.get(
        f"{BASE_URL}/podcasts/episodes/feed",
        headers=headers
    )

    if response.status_code == 200:
        data = response.json()
        episodes = data.get('items', [])
        print(f"获取到 {len(episodes)} 个播客分集")
        if episodes:
            print(f"第一个分集ID: {episodes[0].get('id')}")
            print(f"第一个分集标题: {episodes[0].get('title')}")
        return episodes
    else:
        print(f"获取Feed失败: {response.text}")
        return []

def main():
    # 登录
    token = login_user()
    if not token:
        print("无法登录，请检查后端服务")
        return

    # 创建订阅
    subscription_id = create_subscription(token)

    # 获取Feed数据
    episodes = get_feed_data(token)

    if episodes:
        print("\n成功创建测试数据！")
        print(f"Feed地址: http://localhost:8000/api/v1/podcasts/episodes/feed")
        print(f"前端地址: http://localhost:3000")
        print("\n测试建议:")
        print("1. 打开浏览器访问 http://localhost:3000")
        print("2. 登录使用 test@example.com / Test123456!")
        print("3. 点击Feed标签查看播客列表")
        print("4. 点击任意播客分集，应该跳转到详细页面")

if __name__ == "__main__":
    main()