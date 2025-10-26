import pytest
from app.scanner.link_scanner import LinkScanner
from types import SimpleNamespace

# Dummy executor to inject controlled raw data
class DummyExecutor:
    def __init__(self, raw_response):
        self.raw_response = raw_response

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def run_url(self, url):
        return self.raw_response

@pytest.fixture
def fake_executor():
    """
    Fixture that creates a DummyExecutor with given raw data.
    Usage: fake_executor(raw_dict) -> returns executor instance.
    """
    def _make(raw):
        return DummyExecutor(raw)
    return _make

@pytest.mark.parametrize("raw, expected", [
    # suspicious hidden large iframe
    (
        {
            "error": None,
            "status_code": 200,
            "redirects": [],
            "final_url": "https://evil.com",
            "console_messages": [],
            "cookies": [],
            "load_time_ms": 123,
            "iframes": [
                {
                    "src": "https://google.com/malicious",
                    "width": 900,
                    "height": 700,
                    "opacity": "0",
                    "display": "none",
                    "visibility": "hidden",
                    "sandbox": None
                }
            ]
        },
        {
            "status": "suspicious",
            "min_score": 60,
            "expect_iframe_reason": True
        }
    ),
    # safe iframe (small, visible, with sandbox)
    (
        {
            "error": None,
            "status_code": 200,
            "redirects": [],
            "final_url": "https://safe.com",
            "console_messages": [],
            "cookies": [],
            "load_time_ms": 50,
            "iframes": [
                {
                    "src": "https://example.com",
                    "width": 100,
                    "height": 100,
                    "opacity": "1",
                    "display": "block",
                    "visibility": "visible",
                    "sandbox": "allow-scripts"
                }
            ]
        },
        {
            "status": "safe",
            "exact_score": 10,
            "expect_iframe_reason": False
        }
    )
])
def test_iframe_detection(raw, expected, fake_executor):
    """
    Test that LinkScanner properly classifies pages based on iframe signals,
    and sets risk_score and reasons correctly.
    """
    # Arrange: inject fake raw data
    executor = fake_executor(raw)
    scanner = LinkScanner(executor)

    # Act
    result = scanner.scan("https://test-url/")

    # Assert status
    assert result["status"] == expected["status"], \
        f"Expected status {expected['status']}, got {result['status']}"

    # Assert risk_score
    score = result["risk_score"]
    if expected.get("min_score") is not None:
        assert score >= expected["min_score"], \
            f"Expected score >= {expected['min_score']}, got {score}"
    else:
        assert score == expected["exact_score"], \
            f"Expected score == {expected['exact_score']}, got {score}"

    # Assert that iframe reasons appear only when expected
    reasons = result["reasons"]
    contains_iframe = any("iframe" in reason.lower() for reason in reasons)
    assert contains_iframe is expected["expect_iframe_reason"], \
        f"Expected iframe reason: {expected['expect_iframe_reason']}, got {contains_iframe}"

    # Assert raw payload is preserved
    assert result["raw"] == raw, "Raw data should be passed through unchanged"

    # Additional structure checks
    assert "iframes" in result["raw"], "Raw must include 'iframes' key"
    for frame in result["raw"]["iframes"]:
        # each iframe entry must have the expected keys
        for key in ("src", "width", "height", "opacity", "display", "visibility", "sandbox"):
            assert key in frame, f"Missing '{key}' in iframe data"
