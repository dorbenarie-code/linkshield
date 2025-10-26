"""
Signal detection modules for identifying suspicious patterns in web pages.
"""
from __future__ import annotations

from .network_request_collector import NetworkRequestCollector
from .network_anomaly_signal import NetworkAnomalyDetector
from .js_behavior_signal import detect_js_behaviors
from .iframe_signal import detect_suspicious_iframes
from .visual_signal import detect_visual_signals

__all__ = [
    "NetworkRequestCollector",
    "NetworkAnomalyDetector",
    "detect_js_behaviors",
    "detect_suspicious_iframes",
    "detect_visual_signals",
]

