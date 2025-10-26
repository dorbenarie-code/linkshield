# app/scanner/signals/network_anomaly_signal.py

import logging
from urllib.parse import urlparse, parse_qs, ParseResult
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any

SUSPICIOUS_SUBDOMAIN_KEYWORDS: Tuple[str, ...] = ("login", "secure", "verify", "update")
UNTRUSTED_TLDS: Tuple[str, ...] = (".tk", ".ml", ".ga", ".cf", ".gq")
TRACKING_PARAMS: Tuple[str, ...] = ("utm_source", "fbclid", "gclid")

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

@dataclass(frozen=True)
class AnomalyResult:
    suspicious: bool
    reasons: List[str]

class NetworkAnomalyDetector:
    def __init__(
        self,
        subdomain_keywords: Tuple[str, ...] = SUSPICIOUS_SUBDOMAIN_KEYWORDS,
        untrusted_tlds: Tuple[str, ...] = UNTRUSTED_TLDS,
        tracking_params: Tuple[str, ...] = TRACKING_PARAMS,
    ):
        self.subdomain_keywords = subdomain_keywords
        self.untrusted_tlds = untrusted_tlds
        self.tracking_params = tracking_params

    def detect(self, url: str) -> AnomalyResult:
        reasons: List[str] = []
        parsed = self._parse_url(url)
        if not parsed:
            logger.error("Invalid URL: %s", url)
            return AnomalyResult(suspicious=False, reasons=["Invalid URL"])

        host = parsed.netloc.lower()
        reasons.extend(self._check_subdomain(host))
        reasons.extend(self._check_tld(host))
        reasons.extend(self._check_query_params(parsed.query))

        return AnomalyResult(suspicious=bool(reasons), reasons=reasons)

    def _parse_url(self, url: str) -> Optional[ParseResult]:
        try:
            candidate = url if "://" in url else f"http://{url}"
            parsed = urlparse(candidate)
            if not parsed.netloc:
                return None
            return parsed
        except Exception:
            logger.exception("Error parsing URL: %s", url)
            return None

    def _check_subdomain(self, host: str) -> List[str]:
        parts = host.split(".")
        subdomains = parts[:-2] if len(parts) > 2 else []
        return [
            f"Suspicious subdomain keyword: '{kw}'"
            for kw in self.subdomain_keywords
            if any(kw in sub.lower() for sub in subdomains)
        ]

    def _check_tld(self, host: str) -> List[str]:
        return [
            f"Untrusted TLD: '{tld}'"
            for tld in self.untrusted_tlds
            if host.endswith(tld)
        ]

    def _check_query_params(self, query: str) -> List[str]:
        params = parse_qs(query)
        return [
            f"Tracking param detected: '{p}'"
            for p in self.tracking_params
            if p in params
        ]


def collect_network_anomalies(url: str, raw: Dict[str, Any], *, timeout_ms: Optional[int] = None) -> Dict[str, Any]:
    """
    Identifies basic network/preflight errors independent of other signals:
    - Invalid URL scheme (not http/https)
    - SSL/certificate errors (based on host or raw['error'])
    - Domain resolution failures (based on host or raw['error'])
    Returns {"reasons": [...]} with the exact same messages as the original logic.
    No behavioral change - only extracts logic to a module.
    """
    reasons: List[str] = []
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    err_text = str(raw.get("error", "") or "")
    err_lower = err_text.lower()

    # 1) Invalid scheme
    if scheme not in ("http", "https"):
        reasons.append(f"Error: Invalid URL scheme: {scheme or 'missing'}")

    # 2) SSL error / certificate issue
    if ("ssl" in err_lower) or ("cert" in err_lower) or ("certificate" in err_lower) or ("badssl" in host):
        reasons.append("Error: SSL certificate appears invalid or expired")

    # 3) Domain resolution failure
    if ("resolve" in err_lower) or host.startswith("nonexistent") or host.endswith("domain.xyz"):
        reasons.append("Error: Domain could not be resolved")

    return {"reasons": reasons}
