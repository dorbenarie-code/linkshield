from urllib.parse import urlparse
from typing import List
from .types import SignalResult

SUSPICIOUS_KEYWORDS: List[str] = ["phish", "secure", "login"]

def detect_url_keywords(url: str) -> SignalResult:
    """Unified format: reasons + meta (for future analysis)."""
    domain = (urlparse(url).netloc or "").lower()
    found = [k for k in SUSPICIOUS_KEYWORDS if k in domain]
    reasons = ["Suspicious keywords in URL"] if found else []
    return {"reasons": reasons, "meta": {"found": found, "domain": domain}}

def has_suspicious_url_keyword(url: str) -> bool:
    """Backward compatibility shim for existing usage/tests."""
    return bool(detect_url_keywords(url).get("reasons"))

