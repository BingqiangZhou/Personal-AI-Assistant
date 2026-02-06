"""验证批量删除路由是否正确注册"""
import sys


sys.path.insert(0, ".")

from app.domains.podcast.api.routes import router


print("=" * 80)
print("检查批量删除路由:")
print("=" * 80)

found = False
for route in router.routes:
    if hasattr(route, 'path') and hasattr(route, 'methods'):
        path = route.path
        methods = list(route.methods)

        if 'bulk-delete' in path or ('bulk' in path and 'DELETE' in methods) or ('bulk-delete' in path and 'POST' in methods):
            print("✅ 找到批量删除路由:")
            print(f"   方法: {methods[0]}")
            print(f"   路径: {path}")
            found = True

if not found:
    print("❌ 未找到批量删除路由！")
    print("\n所有 /subscriptions 相关路由:")
    for route in router.routes:
        if hasattr(route, 'path') and hasattr(route, 'methods') and '/subscriptions' in route.path:
            print(f"   {list(route.methods)[0]:8s} {route.path}")
else:
    print("\n✅ 批量删除路由已正确注册")
    print("\n测试建议:")
    print("   POST http://localhost:8000/api/v1/podcasts/subscriptions/bulk-delete")
    print("   Body: {\"subscription_ids\": [1, 2, 3]}")
