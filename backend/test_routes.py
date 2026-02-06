"""测试路由注册顺序"""
import sys


sys.path.insert(0, ".")

from app.domains.podcast.api.routes import router


print("=" * 80)
print("Podcast Router Routes:")
print("=" * 80)

for route in router.routes:
    if hasattr(route, 'path') and hasattr(route, 'methods'):
        path = route.path
        methods = list(route.methods)
        print(f"{methods[0]:8s} {path}")

print("\n" + "=" * 80)
print("Checking bulk delete route:")
print("=" * 80)

bulk_routes = [r for r in router.routes if hasattr(r, 'path') and 'bulk' in r.path]
print(f"Found {len(bulk_routes)} bulk routes:")
for route in bulk_routes:
    if hasattr(route, 'methods'):
        print(f"  {list(route.methods)[0]:8s} {route.path}")

print("\n" + "=" * 80)
print("Checking parameterized subscription routes:")
print("=" * 80)

param_routes = [r for r in router.routes if hasattr(r, 'path') and '{subscription_id}' in r.path]
print(f"Found {len(param_routes)} parameterized routes:")
for route in param_routes:
    if hasattr(route, 'methods'):
        print(f"  {list(route.methods)[0]:8s} {route.path}")

print("\n" + "=" * 80)
print("Route order check:")
print("=" * 80)

subscription_routes = []
for idx, route in enumerate(router.routes):
    if hasattr(route, 'path') and hasattr(route, 'methods') and '/subscriptions' in route.path:
        methods = list(route.methods)
        subscription_routes.append((idx, methods[0], route.path))

print("Subscription routes in order of definition:")
for idx, method, path in subscription_routes:
    marker = "⚠️ BULK" if 'bulk' in path else ""
    marker = "🔑 PARAM" if '{subscription_id}' in path else marker
    print(f"  {idx:3d}. {method:8s} {path:50s} {marker}")

# Check if bulk DELETE comes before parameterized DELETE
bulk_delete_idx = None
param_delete_idx = None

for idx, method, path in subscription_routes:
    if method == 'DELETE' and 'bulk' in path:
        bulk_delete_idx = idx
    elif method == 'DELETE' and '{subscription_id}' in path:
        param_delete_idx = idx

print("\n" + "=" * 80)
print("Routing Order Analysis:")
print("=" * 80)

if bulk_delete_idx and param_delete_idx:
    print(f"Bulk DELETE route index:  {bulk_delete_idx}")
    print(f"Param DELETE route index: {param_delete_idx}")

    if bulk_delete_idx < param_delete_idx:
        print("✅ Route order is CORRECT (bulk comes before parameterized)")
    else:
        print("❌ Route order is WRONG (parameterized comes before bulk)")
        print("   FIX: Move bulk DELETE route definition before parameterized DELETE")
else:
    if not bulk_delete_idx:
        print("❌ Bulk DELETE route NOT FOUND!")
    if not param_delete_idx:
        print("❌ Parameterized DELETE route NOT FOUND!")
