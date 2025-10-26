import os
import signal
import logging
from pathlib import Path
from typing import Dict, Any, List
from contextlib import suppress
from PIL import Image, UnidentifiedImageError
import pytesseract

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

OCR_TIMEOUT = 10
MAX_IMAGE_SIZE = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}
MAX_OCR_LENGTH = 2000

class OCRTimeout(Exception):
    """Raised when OCR takes too long."""
    pass

def _timeout_handler(signum, frame):
    raise OCRTimeout("OCR operation timed out")

def _load_image(path: Any) -> Image.Image:
    """
    Validate that `path` exists, extension, and size, then load it.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Screenshot not found: {p}")
    if p.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Unsupported file extension: {p.suffix}")
    if p.stat().st_size > MAX_IMAGE_SIZE:
        raise ValueError(f"Image too large: {p.stat().st_size} bytes")
    try:
        return Image.open(p)
    except UnidentifiedImageError:
        raise ValueError("Invalid or unreadable image format.")

def _extract_ocr_text(image: Image.Image) -> str:
    """
    Run OCR with timeout, trim whitespace, log partial result, and enforce max length.
    """
    signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(OCR_TIMEOUT)
    try:
        raw_text = pytesseract.image_to_string(image) or ""
    finally:
        with suppress(Exception):
            signal.alarm(0)

    text = raw_text.strip()
    logger.debug("Extracted OCR (partial): %s", text[:100])
    return text[:MAX_OCR_LENGTH]

def _load_keywords() -> List[str]:
    """Load suspicious keywords from environment."""
    env = os.getenv("OCR_KEYWORDS", "login,paypal,verify")
    return [kw.strip().lower() for kw in env.split(",") if kw.strip()]

def _check_keywords(ocr_text: str, keywords: List[str]) -> List[str]:
    """Return list of found keywords in ocr_text."""
    lower = ocr_text.lower()
    return [kw for kw in keywords if kw in lower]

def detect_visual_signals(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point:
    - Loads & validates image
    - Runs OCR with timeout
    - Cuts text to 2000 chars
    - Checks for suspicious keywords
    """
    result = {"suspicious": False, "alerts": [], "ocr_text": ""}

    screenshot = raw.get("screenshot")
    if not screenshot:
        logger.debug("No screenshot path provided")
        return result

    try:
        img = _load_image(screenshot)
        ocr_text = _extract_ocr_text(img)
        result["ocr_text"] = ocr_text
        raw["ocr_text"] = ocr_text

    except OCRTimeout as e:
        logger.error("OCR timed out: %s", e)
        return result
    except Exception as e:
        logger.warning("Cannot process image: %s", e)
        return result

    keywords = _load_keywords()
    found = _check_keywords(ocr_text, keywords)
    for kw in found:
        logger.warning("⚠️ OCR suspicious keyword found: '%s'", kw)
        result["alerts"].append(f"Suspicious visual keyword: '{kw}'")
    if found:
        result["suspicious"] = True

    logger.debug("Final OCR text length: %d", len(ocr_text))
    return result
