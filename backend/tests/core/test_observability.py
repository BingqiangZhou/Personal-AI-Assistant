from app.core.observability import ObservabilityThresholds, build_observability_snapshot


def test_build_observability_snapshot_has_expected_sections():
    snapshot = build_observability_snapshot(
        performance_metrics={
            "summary": {
                "global_p95_ms": 120.0,
                "global_error_rate": 0.01,
                "total_requests": 100,
                "total_errors": 1,
            }
        },
        db_pool={"occupancy_ratio": 0.5},
        redis_runtime={
            "commands": {"avg_ms": 2.0, "max_ms": 9.0, "total_count": 40},
            "cache": {"hit_rate": 0.8, "hits": 80, "misses": 20},
        },
    )

    assert snapshot["summary"]["overall_status"] == "ok"
    assert snapshot["summary"]["alerts_count"] == 0
    assert snapshot["checks"]
    assert snapshot["alerts"] == []


def test_build_observability_snapshot_emits_alerts_on_threshold_breach():
    snapshot = build_observability_snapshot(
        performance_metrics={
            "summary": {
                "global_p95_ms": 1500.0,
                "global_error_rate": 0.2,
                "total_requests": 200,
                "total_errors": 40,
            }
        },
        db_pool={"occupancy_ratio": 0.98},
        redis_runtime={
            "commands": {"avg_ms": 70.0, "max_ms": 250.0, "total_count": 120},
            "cache": {"hit_rate": 0.2, "hits": 20, "misses": 80},
        },
        thresholds=ObservabilityThresholds(
            api_p95_ms=300.0,
            api_error_rate=0.05,
            db_pool_occupancy_ratio=0.9,
            redis_command_avg_ms=20.0,
            redis_command_max_ms=100.0,
            redis_cache_hit_rate_min=0.7,
            redis_cache_lookups_min=10,
        ),
    )

    alert_names = {alert["name"] for alert in snapshot["alerts"]}
    assert snapshot["summary"]["overall_status"] in {"warning", "critical"}
    assert "api_latency_p95" in alert_names
    assert "api_error_rate" in alert_names
    assert "db_pool_occupancy" in alert_names
    assert "redis_command_avg" in alert_names
    assert "redis_command_max" in alert_names
    assert "redis_cache_hit_rate" in alert_names

