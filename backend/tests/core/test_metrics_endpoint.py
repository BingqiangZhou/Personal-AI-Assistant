from fastapi.testclient import TestClient

from app.main import app


def test_metrics_endpoint_includes_runtime_sections():
    client = TestClient(app)
    client.get("/")

    response = client.get("/metrics")

    assert response.status_code == 200
    payload = response.json()
    assert "request_counts" in payload
    assert "response_times" in payload
    assert "error_counts" in payload
    assert "summary" in payload
    assert "global_p95_ms" in payload["summary"]
    assert "db_pool" in payload
    assert "redis_runtime" in payload
    assert "commands" in payload["redis_runtime"]
    assert "cache" in payload["redis_runtime"]
    for endpoint_stats in payload["response_times"].values():
        assert "p95_ms" in endpoint_stats
