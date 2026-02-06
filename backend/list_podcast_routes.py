from app.domains.podcast.api.routes import router


for route in router.routes:
    methods = getattr(route, "methods", "N/A")
    print(f"{methods} {route.path}")
