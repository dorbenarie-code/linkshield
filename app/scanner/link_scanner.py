# scanner/link_scanner.py
from __future__ import annotations
from dataclasses import dataclass, field, asdict
import logging
from typing import Any, Dict, List, cast
from urllib.parse import urlparse
import ipaddress
try:
    from app.scanner.signals.js_behavior_signal import detect_js_behaviors  # type: ignore[reportMissingImports]
except Exception:
    def detect_js_behaviors(raw: Dict[str, Any]) -> Dict[str, Any]:  # fallback
        return {}
try:
    from app.scanner.signals.iframe_signal import detect_suspicious_iframes  # type: ignore[reportMissingImports]
except Exception:
    def detect_suspicious_iframes(raw: Dict[str, Any]) -> Dict[str, Any]:  # fallback
        return {}
try:
    from app.scanner.signals.redirect_signal import detect_redirects  # type: ignore[reportMissingImports]
except Exception:
    def detect_redirects(_: Any, threshold: int = 2) -> Dict[str, Any]:  # fallback
        return {"reasons": []}
try:
    from app.scanner.signals.network_anomaly_signal import collect_network_anomalies  # type: ignore[reportMissingImports]
except Exception:
    def collect_network_anomalies(url: str, raw: Dict[str, Any], *, timeout_ms: Any = None) -> Dict[str, Any]:  # fallback
        return {"reasons": []}
try:
    from app.scanner.signals.visual_signal import detect_visual_signals  # type: ignore[reportMissingImports]
except Exception:
    def detect_visual_signals(raw: Dict[str, Any]) -> Dict[str, Any]:  # fallback
        return {}
try:
    from app.scanner.signals.url_keyword_signal import detect_url_keywords  # type: ignore[reportMissingImports]
except Exception:
    def detect_url_keywords(url: str) -> Dict[str, Any]:  # fallback
        return {"reasons": []}

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
def _norm_reasons(x: Any) -> List[str]:
    """נרמול reasons לרשימת strings נקייה"""
    if not isinstance(x, list):
        return []
    items: List[Any] = cast(List[Any], x)
    out: List[str] = []
    for r in items:
        if isinstance(r, str):
            out.append(r)
        elif r is not None:
            out.append(str(r))
    return out

@dataclass
class ScanResult:
    """
    Holds the aggregated scan data and evaluation outcome.
    Returned as a dict (via asdict) for API compatibility.
    """
    url: str
    raw: Dict[str, Any] = field(default_factory=dict)
    final_url: str = ""
    status: str = "clean"
    risk_score: int = 0
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert ScanResult to dict. Allows future customization."""
        d = asdict(self)
        d["reasons"] = _norm_reasons(d.get("reasons", []))
        return d

class LinkScanner:
    """
    Orchestrates fetching a URL and evaluating it against multiple security signals.
    """
    SUSPICIOUS_THRESHOLD = 50
    MALICIOUS_THRESHOLD = 95  
    MAX_SCORE = 100
    SAFE_IFRAME_BASE = 10  # baseline score for non-suspicious iframes
    SIGNAL_WEIGHTS = {
        "console": 10,
        "redirect": 30,
        "url_keyword": 30,
        "ocr": 30,
        "iframe": 60,  
        "js": 25,
    }
    SUSPICIOUS_REDIRECT_COUNT = 2

    def __init__(self, executor: Any) -> None:
        """
        :param executor: object with run_url(url) -> raw data dict
                         Should implement the Executor protocol from app.scanner.types
        """
        self.executor = executor
        self.logger = logger

    def scan(self, url: str) -> Dict[str, Any]:
        """
        Scan a URL and return a dict representing ScanResult.
        TODO: Add retry/backoff/fallback logic for transient errors.
        """
        normalized = self.normalize_url(url)
        self.validate_url(normalized)
        result = ScanResult(url=normalized)
        try:
            raw = self.executor.run_url(normalized)
            # נקבל baseline risk_score מה-raw (אם קיים) אבל לא status - _evaluate תחשב את הסופי
            baseline_score = raw.get("risk_score", 0) if isinstance(raw.get("risk_score"), (int, float)) else 0
            result.risk_score = baseline_score
            # status ו-reasons ייבנו ב-_evaluate

            # --- Preflight: network/SSL/DNS anomalies (moved to signal) ---
            net_anomalies = collect_network_anomalies(normalized, raw)
            if net_anomalies["reasons"]:
                # הוספה ללא כפילויות
                for e in net_anomalies["reasons"]:
                    if e not in result.reasons:
                        result.reasons.append(e)
                # שגיאות כאלה הן קריטיות → מרימים ציון וסטטוס
                result.risk_score = self.MAX_SCORE
                result.status = "malicious"

            # --- Redirect heuristic (לפי הטסטים דורש reason, הציון יתווסף ב-_evaluate) ---
            redirects_any: Any = raw.get("redirects") or []
            if isinstance(redirects_any, list):
                redir_list: List[Any] = cast(List[Any], redirects_any)
                if len(redir_list) > 0:
                    # רק מוסיפים reason אם אין - הציון יתווסף ב-_evaluate
                    if not any("redirect" in str(r).lower() for r in result.reasons):
                        result.reasons.append("Redirect chain detected")

            # Organize all signals under 'signals' namespace
            signals: Dict[str, Dict[str, Any]] = {
                "iframe": detect_suspicious_iframes(raw),
                "visual": detect_visual_signals(raw),
                "js": detect_js_behaviors(raw)
            }
            raw["signals"] = signals
            result.raw = raw
            result.final_url = raw.get("final_url", "")
            self._evaluate(raw, signals, result)

            # --- Baseline scoring: safe iframes get minimal score ---
            iframes_any: Any = raw.get("iframes") or []
            if isinstance(iframes_any, list) and len(cast(List[Any], iframes_any)) > 0:
                # If there are iframes but signal didn't flag them as suspicious, apply baseline score
                has_iframe_reason = any("iframe" in str(r).lower() for r in result.reasons)
                if not has_iframe_reason:
                    result.risk_score = max(result.risk_score, self.SAFE_IFRAME_BASE)

        except Exception as e:
            self.logger.exception("Unhandled exception during scan")
            result.status = "malicious"
            result.risk_score = self.MAX_SCORE
            result.reasons.append(f"Unhandled error: {e}")
        return result.to_dict()

    @staticmethod
    def normalize_url(raw_url: str) -> str:
        """
        Normalize the URL (add https:// if missing).
        """
        parsed = urlparse(raw_url)
        if not parsed.scheme:
            raw_url = "https://" + raw_url
        return raw_url

    @staticmethod
    def validate_url(url: str) -> None:
        """
        Validate the URL for structure and block private/local addresses.
        Raises ValueError if invalid or unsafe.
        """
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError(f"Invalid URL: '{url}'")
        if LinkScanner.is_private_or_local(url):
            logger.warning(f"Blocked scan for private/local address: {url}")
            raise ValueError("Scanning local/private addresses is not allowed")

    @staticmethod
    def is_private_or_local(url: str) -> bool:
        """
        Check if the URL is private/local (file://, localhost, 127.0.0.1, etc.).
        If True, skip scanning.
        """
        parsed = urlparse(url)
        if parsed.scheme == "file":
            return True
        host = parsed.hostname
        if not host:
            return False
        if host in ("localhost", "127.0.0.1", "::1"):
            return True
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback:
                return True
        except (ValueError, TypeError):
            pass
        return False

    def _evaluate(self, raw: Dict[str, Any], signals: Dict[str, Dict[str, Any]], result: ScanResult) -> None:
        # 1. fetch errors → malicious
        if raw.get("error"):
            self._mark_malicious(result, f"Fetch error: {raw['error']}")
            return
        # 2. HTTP errors → malicious
        code = raw.get("status_code", 0)
        if code >= 400:
            self._mark_malicious(result, f"HTTP error code {code}")
            return
        # 3. Console messages
        if raw.get("console_messages"):
            self._mark_suspicious(
                result,
                "Detected console messages",
                score_increment=self.SIGNAL_WEIGHTS["console"]
            )
        # 4. Multiple redirects (signal, unified result)
        thr = getattr(self, "SUSPICIOUS_REDIRECT_COUNT", 2)
        rd = detect_redirects(raw, threshold=thr)
        for r in rd.get("reasons", []):
            self._mark_suspicious(result, r, score_increment=self.SIGNAL_WEIGHTS["redirect"])
        # 5. URL keywords (signal, unified result)
        url_sig = detect_url_keywords(result.final_url)
        for r in url_sig.get("reasons", []):
            self._mark_suspicious(result, r, score_increment=self.SIGNAL_WEIGHTS["url_keyword"])
        # 6. Visual/OCR signals
        self._apply_suspicious_signals(result, signals["visual"], "alerts", self.SIGNAL_WEIGHTS["ocr"])
        # 7. Iframe signals
        if signals["iframe"].get("suspicious_iframes_found"):
            self._apply_suspicious_signals(result, signals["iframe"], "reasons", self.SIGNAL_WEIGHTS["iframe"])
        # 8. JS analysis signals
        if signals["js"].get("suspicious_js_found"):
            self._apply_suspicious_signals(result, signals["js"], "alerts", self.SIGNAL_WEIGHTS.get("js", 25))
        # 10. final status
        if result.risk_score >= self.MALICIOUS_THRESHOLD:
            result.status = "malicious"
        elif result.risk_score >= self.SUSPICIOUS_THRESHOLD:
            result.status = "suspicious"
        else:
            result.status = "safe"

    def _apply_suspicious_signals(self, result: ScanResult, source_dict: Dict[str, Any], key: str, score: int) -> None:
        # Guard טיפוסי קל – למקרה שמקורית זה לא בדיוק List[str]
        alerts_list: List[Any] = cast(List[Any], source_dict.get(key, []) or [])

        # נרמול ל-strings ומניעת כפילויות
        reasons: List[str] = result.reasons
        added_count = 0
        for a in alerts_list:
            s: str = a if isinstance(a, str) else (str(a) if a is not None else "")
            if s and s not in reasons:  # בלי כפילויות
                reasons.append(s)
                added_count += 1
        
        # עדכון רק אם באמת הוספנו alerts
        if added_count > 0:
            result.reasons = reasons
            result.risk_score = min(self.MAX_SCORE, result.risk_score + score)

    def _mark_suspicious(
        self,
        result: ScanResult,
        reason: str,
        score_increment: int
    ) -> None:
        if reason in result.reasons:
            return
        result.reasons.append(reason)
        result.risk_score = min(self.MAX_SCORE, result.risk_score + score_increment)

    def _mark_malicious(self, result: ScanResult, reason: str) -> None:
        if reason not in result.reasons:
            result.reasons.append(reason)
        result.status = "malicious"
        result.risk_score = self.MAX_SCORE

    # הוחלף ע"י has_multiple_redirects ב-signal; אין שינוי התנהגות.

    # הוחלף ע"י has_suspicious_url_keyword ב-signal; אין שינוי התנהגות.

    # הוחלף ע"י collect_network_anomalies ב-signal; אין שינוי התנהגות.

    # הוחלף ע"י detect_suspicious_iframes (signal); אין שינוי התנהגות.
