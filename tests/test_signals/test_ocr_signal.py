import pytest
from pathlib import Path
from PIL import Image
from app.scanner.signals.visual_signal import detect_visual_signals

@pytest.fixture
def resources_dir() -> Path:
    """
    Return the test resources directory path.
    """
    return Path("tests/resources")

@pytest.fixture
def valid_raw_with_screenshot(resources_dir: Path):
    """
    Raw data containing the OCR test image with suspicious keywords.
    """
    return {"screenshot": resources_dir / "test_ocr.png", "console_messages": []}

@pytest.fixture
def raw_without_keywords(tmp_path):
    """
    Raw data with a blank image (no keywords).
    """
    blank = tmp_path / "blank.png"
    Image.new("RGB", (200, 100), color="white").save(blank)
    return {"screenshot": blank, "console_messages": []}

def test_ocr_detects_suspicious_keyword(valid_raw_with_screenshot):
    result = detect_visual_signals(valid_raw_with_screenshot)
    assert result.get("suspicious") is True, "Expected suspicious=True when keywords present"
    alerts = result.get("alerts", [])
    suspicious_keywords = ["paypal", "login", "verify"]
    matched = [
        kw for kw in suspicious_keywords
        if any(kw in alert.lower() for alert in alerts)
    ]
    assert matched, f"Expected at least one suspicious keyword in alerts, got: {alerts}"
    assert "ocr_error" not in result

def test_no_keywords_is_safe(raw_without_keywords):
    """
    Verify that a blank image (no text) returns a safe result.
    """
    result = detect_visual_signals(raw_without_keywords)
    assert result.get("suspicious") is False, "Expected suspicious=False when no keywords found"
    assert isinstance(result.get("alerts"), list), "Alerts should be a list"
    assert result["alerts"] == [], f"Expected no alerts, got: {result['alerts']}"
    assert len(result["ocr_text"].strip()) == 0, (
        f"OCR text unexpectedly non-empty: '{result['ocr_text']}'"
    )
    assert "ocr_error" not in result

def test_missing_screenshot_key_returns_safe():
    """
    Raw without 'screenshot' key should return a safe result without exception.
    """
    result = detect_visual_signals({"console_messages": []})
    assert result["suspicious"] is False
    assert result["alerts"] == []
    assert "ocr_error" not in result

def test_invalid_screenshot_path_returns_safe(resources_dir: Path):
    """
    Non-existent screenshot path should return a safe result without exception.
    """
    bad_raw = {"screenshot": resources_dir / "not_real.png", "console_messages": []}
    result = detect_visual_signals(bad_raw)
    assert result["suspicious"] is False
    assert result["alerts"] == []
    assert "ocr_error" not in result

def test_corrupt_image_returns_safe(resources_dir: Path):
    """
    Invalid (corrupt) image file should return a safe result without exception.
    """
    path = resources_dir / "invalid_file.png"
    assert path.exists(), f"'{path.name}' is missing"
    result = detect_visual_signals({"screenshot": path, "console_messages": []})
    assert result["suspicious"] is False
    assert result["alerts"] == []
    assert "ocr_error" not in result
