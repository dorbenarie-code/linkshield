import pytest
from pathlib import Path
from typing import Any, Dict, List, cast

# Runtime-safe import with static-checker silence:
try:
    from app.scanner.link_scanner import LinkScanner  # type: ignore[reportMissingImports]
except Exception:
    # fallback ל-workspaces שלא פתחו מהשורש: מוסיפים את שורש הפרויקט ל-sys.path ורוכשים שוב
    import sys
    from pathlib import Path as _P
    ROOT = str(_P(__file__).resolve().parents[2])
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    from app.scanner.link_scanner import LinkScanner  # type: ignore[reportMissingImports]

class StubExecutor:
    def __init__(self, raw: Dict[str, Any]):
        self._raw: Dict[str, Any] = raw

    def run_url(self, url: str, retries: int = 0) -> Dict[str, Any]:
        return self._raw

@pytest.fixture
def blank_screenshot() -> Path:
    """
    Path to a blank image used when there's no suspicious text.
    """
    return Path(__file__).parent.parent / "resources" / "blank.png"

@pytest.fixture
def default_raw(blank_screenshot: Path) -> Dict[str, Any]:
    """
    Provide raw data with redirects and a hidden iframe, using the screenshot fixture.
    """
    return {
        "final_url": "https://example.com",
        "redirects": ["https://step1.com", "https://step2.com"],
        "status_code": 200,
        "console_messages": [],
        "iframes": [
            {
                "width": 1000,
                "height": 800,
                "opacity": 0.0,
                "display": "none",
                "visibility": "hidden",
                "src": "https://paypal.com",
                "sandbox": None
            }
        ],
        "screenshot": blank_screenshot
    }

@pytest.fixture
def scanner(default_raw: Dict[str, Any]) -> Any:
    """
    Create a LinkScanner instance using StubExecutor with default raw data.
    """
    return cast(Any, LinkScanner(StubExecutor(default_raw)))

@pytest.fixture
def suspicious_screenshot() -> Path:
    """
    Path to an image containing suspicious OCR text (e.g., "PayPal Login").
    """
    return Path(__file__).parent.parent / "resources" / "test_ocr.png"

def test_redirect_and_iframe_combination(scanner: Any) -> None:
    """
    Combined redirect + hidden iframe should be flagged as suspicious,
    and at least two distinct reasons must be reported.
    """
    result: Dict[str, Any] = cast(Dict[str, Any], scanner.scan("https://test.com"))

    # status
    assert result["status"] == "suspicious", "Expected status to be suspicious"

    # risk_score
    assert isinstance(result["risk_score"], (int, float)), "risk_score must be numeric"
    assert result["risk_score"] >= 50, "Expected risk_score >= 50 for combined threats"

    # reasons content
    reasons: List[str] = [str(r).lower() for r in cast(List[Any], result.get("reasons", []))]
    assert any("redirect" in r for r in reasons), "Missing redirect reason"
    assert any("iframe" in r or "sandbox" in r for r in reasons), "Missing iframe/sandbox reason"

    # bonus: check at least two reasons reported
    assert len(reasons) >= 2, f"Expected at least 2 reasons, got {len(reasons)}"

def test_iframe_and_ocr_combination(suspicious_screenshot: Path) -> None:
    """
    שילוב של iframe מוסתר + טקסט חשוד בתמונה ⇒ status = malicious
    """
    raw_data: Dict[str, Any] = {
        "final_url": "https://phishing.com",
        "redirects": [],
        "status_code": 200,
        "console_messages": [],
        "iframes": [
            {
                "width": 1200,
                "height": 900,
                "opacity": 0.0,
                "display": "none",
                "visibility": "hidden",
                "src": "https://paypal.com",
                "sandbox": None
            }
        ],
        "screenshot": suspicious_screenshot
    }
    scanner: Any = cast(Any, LinkScanner(StubExecutor(raw_data)))

    # Act
    result: Dict[str, Any] = cast(Dict[str, Any], scanner.scan("https://fake.com"))

    # Assert status and risk score
    assert result["status"] == "malicious", f"Expected malicious, got {result['status']}"
    assert isinstance(result["risk_score"], (int, float)), "risk_score must be numeric"
    assert result["risk_score"] >= 90, f"Expected risk_score ≥ 90, got {result['risk_score']}"

    # Assert reasons include both iframe and OCR signals
    reasons: List[str] = [str(r).lower() for r in cast(List[Any], result.get("reasons", []))]
    assert any("iframe" in r or "sandbox" in r for r in reasons), "Missing iframe-related reason"
    assert any("paypal" in r or "login" in r for r in reasons), "Missing OCR keyword reason"

    # Bonus: ensure at least two distinct reasons reported
    assert len(reasons) >= 2, f"Expected ≥ 2 reasons, got {len(reasons)}"

def test_scan_clean_url_returns_clean(blank_screenshot: Path) -> None:
    """
    Given a legit URL with no suspicious signals,
    When scanning is performed,
    Then the result should be:
      - status "clean"
      - risk_score 0
      - no reasons
    """
    # Arrange
    raw_data: Dict[str, Any] = {
        "final_url": "https://legit-site.com",
        "redirects": [],
        "status_code": 200,
        "console_messages": [],
        "iframes": [],
        "screenshot": blank_screenshot  # a blank image: no text
    }
    executor: StubExecutor = StubExecutor(raw_data)
    scanner: Any = cast(Any, LinkScanner(executor))

    # Act
    scan_result: Dict[str, Any] = cast(Dict[str, Any], scanner.scan(cast(str, raw_data["final_url"])))

    # Assert
    assert scan_result["status"] == "safe", \
        f"Expected status='safe' (clean URL), got: {scan_result['status']}"
    assert scan_result["risk_score"] == 0, \
        f"Expected risk_score=0, got: {scan_result['risk_score']}"
    assert scan_result["reasons"] == [], \
        f"Expected no reasons, got: {scan_result['reasons']}"
