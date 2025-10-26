from __future__ import annotations
from typing import Tuple, List, Dict, Any, Optional
import logging
import time
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

@dataclass
class ExecutionResult:
    """
    Data class representing the result of running a URL scan.
    """
    url: str
    status_code: int
    final_url: str
    load_time_ms: int
    redirects: List[str] = field(default_factory=list)
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    console_messages: List[Dict[str, Any]] = field(default_factory=list)
    iframes: List[Dict[str, Any]] = field(default_factory=list)
    screenshot: Optional[str] = None
    error: Optional[str] = None
    risk_score: int = 0
    status: str = "unknown"  # 'safe' | 'suspicious' | 'malicious'
    reasons: List[str] = field(default_factory=list)

class URLValidator:
    @staticmethod
    def validate(url: str) -> None:
        # type is already str by signature; בדיקת isinstance מיותרת
        if not url or not url.strip():
            raise ValueError("URL must be a non-empty string")
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid URL format: {url}")

class ThreatAnalyzer:
    @staticmethod
    def analyze(url: str) -> Tuple[str, int, List[str]]:
        reasons: List[str] = []
        scheme = urlparse(url).scheme.lower()

        # 1) Invalid scheme
        if scheme not in ("http", "https"):
            reasons.append(f"Error: Invalid URL scheme: {scheme}")
            return "malicious", 100, reasons

        # 2) Suspicious keyword
        if "login" in url.lower():
            reasons.append("Suspicious keyword detected: 'login'")
            return "suspicious", 60, reasons

        # 3) Expired SSL test domain
        if "badssl.com" in url.lower():
            reasons.append("Error: SSL certificate appears expired")
            return "malicious", 100, reasons

        # 4) Simulated HTTP error
        if "status/404" in url.lower():
            reasons.append("Error: HTTP 404 error simulated")
            return "malicious", 100, reasons

        # 5) Redirect indicator
        if "redirect" in url.lower():
            reasons.append("Multiple redirects detected")
            return "suspicious", 60, reasons

        # 6) Fake/unresolvable domain
        host = urlparse(url).netloc.lower()
        if host.startswith("nonexistent") or host.endswith("domain.xyz"):
            reasons.append("Error: Domain could not be resolved")
            return "malicious", 100, reasons

        # 7) Known-safe test domains
        if any(domain in url.lower() for domain in ("wikipedia.org", "httpbin.org/html")):
            return "safe", 10, []

        # Default: safe
        return "safe", 10, []

class FakeExecutor:
    """
    Simulates fetching a URL and applies ThreatAnalyzer rules.
    Compatible with the Executor protocol (run_url -> Dict[str, Any]).
    """
    def __init__(self, timeout_ms: int = 3000) -> None:
        self.timeout_ms = timeout_ms

    def __enter__(self) -> "FakeExecutor":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass

    def run_url(self, url: str) -> Dict[str, Any]:
        start = time.time()
        try:
            URLValidator.validate(url)
            status, risk_score, reasons = ThreatAnalyzer.analyze(url)
            error = None
        except Exception as e:
            logger.error("Validation/analysis error: %s", e)
            status, risk_score, reasons = "malicious", 100, [str(e)]
            error = str(e)

        load_time_ms = int((time.time() - start) * 1000)
        if load_time_ms > self.timeout_ms:
            reasons.append("Load time exceeded timeout")
            if status == "safe":
                status, risk_score = "suspicious", 60

        result = ExecutionResult(
            url=url,
            status_code=200 if error is None else 500,
            final_url=url,
            load_time_ms=load_time_ms,
            redirects=[],
            cookies=[],
            console_messages=[],
            iframes=[],
            screenshot=None,
            error=error,
            risk_score=risk_score,
            status=status,
            reasons=reasons,
        )
        return asdict(result)
