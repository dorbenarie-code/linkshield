# app/scanner/signals/network_signal.py

import logging
from urllib.parse import urlparse, parse_qs, ParseResult
from dataclasses import dataclass
from typing import List, Optional, Tuple

# —————— Configuration ——————
SUSPICIOUS_SUBDOMAIN_KEYWORDS: Tuple[str, ...] = (
    "login", "secure", "verify", "update"
)
UNTRUSTED_TLDS: Tuple[str, ...] = (
    ".tk", ".ml", ".ga", ".cf", ".gq"
)
TRACKING_PARAMS: Tuple[str, ...] = (
    "utm_source", "fbclid", "gclid"
)

# —————— Logger setup ——————
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
)
logger.addHandler(_handler)


# —————— Data model ——————
@dataclass(frozen=True)
class AnomalyResult:
    suspicious: bool
    reasons: List[str]


# —————— Detector ——————
class NetworkAnomalyDetector:
    """
    Detect suspicious patterns in URLs: subdomains, TLDs, query params, path.
    """

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
        """
        Analyze the URL and return AnomalyResult.
        Prepends 'http://' if no scheme, handles parse errors.
        """
        reasons: List[str] = []
        parsed = self._parse_url(url)
        if not parsed:
            logger.error("Invalid URL: %s", url)
            return AnomalyResult(suspicious=False, reasons=["Invalid URL"])

        host = parsed.netloc.lower()
        reasons.extend(self._check_subdomain(host))
        reasons.extend(self._check_tld(host))
        reasons.extend(self._check_query_params(parsed.query))
        reasons.extend(self._check_path(parsed.path))

        if reasons:
            for reason in reasons:
                logger.warning("Anomaly detected: %s — URL: %s", reason, url)
        else:
            logger.info("No anomalies for URL: %s", url)

        return AnomalyResult(suspicious=bool(reasons), reasons=reasons)

    def _parse_url(self, url: str) -> Optional[ParseResult]:
        """
        Safely parse URL; ensure it has a scheme and strip whitespace.
        Returns ParseResult or None.
        """
        try:
            candidate = url.strip()
            candidate = candidate if "://" in candidate else f"http://{candidate}"
            parsed = urlparse(candidate)
            if not parsed.netloc:
                return None
            return parsed
        except Exception:
            logger.exception("Error parsing URL: %s", url)
            return None

    def _check_subdomain(self, host: str) -> List[str]:
        """
        Return all suspicious subdomain keywords found.
        """
        parts = host.split(".")
        subdomains = parts[:-2] if len(parts) > 2 else []
        return [
            f"Suspicious subdomain keyword: '{kw}'"
            for kw in self.subdomain_keywords
            if any(kw in sub.lower() for sub in subdomains)
        ]

    def _check_tld(self, host: str) -> List[str]:
        """
        Return all untrusted TLDs matched.
        """
        return [
            f"Untrusted TLD: '{tld}'"
            for tld in self.untrusted_tlds
            if host.endswith(tld)
        ]

    def _check_query_params(self, query: str) -> List[str]:
        """
        Flag any tracking parameters present in the query string.
        """
        params = parse_qs(query)
        return [
            f"Tracking param detected: '{p}'"
            for p in self.tracking_params
            if p in params
        ]

    def _check_path(self, path: str) -> List[str]:
        """
        (Minor enhancement) Flag suspicious keywords in the URL path.
        """
        lowered = path.lower()
        return [
            f"Suspicious keyword in path: '{kw}'"
            for kw in self.subdomain_keywords
            if kw in lowered
        ]
