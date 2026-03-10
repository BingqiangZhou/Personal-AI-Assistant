from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import app.core.providers as providers_module
from app.core.providers import get_redis_client


def test_testclient_compat_and_redis_dependency_cleanup(monkeypatch):
    closed_events: list[str] = []

    class FakeRedis:
        async def close(self) -> None:
            closed_events.append("closed")

    monkeypatch.setattr(providers_module, "PodcastRedis", FakeRedis)

    app = FastAPI()

    @app.get("/ping")
    async def ping(_: FakeRedis = Depends(get_redis_client)):
        return {"status": "ok"}

    with TestClient(app) as client:
        response = client.get("/ping")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert closed_events == ["closed"]
