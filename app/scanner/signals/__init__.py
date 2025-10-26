"""
Signal detection modules for identifying suspicious patterns in web pages.
"""
from __future__ import annotations

from .network_request_collector import NetworkRequestCollector
from .network_anomaly_signal import collect_network_anomalies
from .js_behavior_signal import detect_js_behaviors
from .iframe_signal import detect_suspicious_iframes
from .visual_signal import detect_visual_signals
from .url_keyword_signal import has_suspicious_url_keyword
from .redirect_signal import has_multiple_redirects

__all__ = [
    "NetworkRequestCollector",
    "collect_network_anomalies",
    "detect_js_behaviors",
    "detect_suspicious_iframes",
    "detect_visual_signals",
    "has_suspicious_url_keyword",
    "has_multiple_redirects",
]

