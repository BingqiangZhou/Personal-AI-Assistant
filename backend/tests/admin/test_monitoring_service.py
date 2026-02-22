from app.admin.monitoring import SystemMonitorService


def test_system_monitor_service_collects_expected_sections():
    service = SystemMonitorService()
    payload = service.get_all_metrics()

    assert "system_info" in payload
    assert "cpu" in payload
    assert "memory" in payload
    assert "disk" in payload
    assert "network" in payload
    assert "updated_at" in payload

    assert "hostname" in payload["system_info"]
    assert "usage_percent" in payload["cpu"]
    assert "percent" in payload["memory"]
    assert "partitions" in payload["disk"]
    assert "interfaces" in payload["network"]
