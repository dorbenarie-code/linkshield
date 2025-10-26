import pytest
from app.services.scan_service import ScanService, ScanResult
from app.scanner.exceptions import ScanError

class DummyExecutor:
    def __init__(self, timeout=None):
        pass
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    def run_url(self, url):
        if "fail" in url:
            raise Exception("Executor failure")
        return {
            "url": url,
            "final_url": url,
            "status": "safe",
            "risk_score": 10,
            "reasons": ["Test reason"],
            "raw": {"dummy": True}
        }

def test_valid_scan(monkeypatch):
    service = ScanService(executor_cls=DummyExecutor)
    result = service.run("https://example.com")
    assert result["url"] == "https://example.com"
    assert result["status"] == "safe"
    assert result["risk_score"] == 10
    assert result["reasons"] == ["Test reason"]
    assert result["raw"]["dummy"] is True

def test_invalid_url():
    service = ScanService(executor_cls=DummyExecutor)
    with pytest.raises(ValueError):
        service.run("not_a_url")

def test_executor_failure():
    service = ScanService(executor_cls=DummyExecutor)
    with pytest.raises(ScanError):
        service.run("https://fail.com") 