# scanner/signals/iframe_signal.py

import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

DEFAULT_SUSPICIOUS_DOMAINS: Tuple[str, ...] = ("google.com", "microsoft.com", "paypal.com")
MIN_LARGE_WIDTH, MIN_LARGE_HEIGHT = 800, 600
MAX_TRACKER_WIDTH, MAX_TRACKER_HEIGHT = 2, 2

def _to_int(value: Any, default: int = 0) -> int:
    """Convert value to int, return default on failure."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def _to_float(value: Any, default: float = 1.0) -> float:
    """Convert value to float, return default on failure."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

def _is_hidden(opacity: float, display: str, visibility: str) -> bool:
    """Determine if an iframe is effectively hidden."""
    return opacity < 0.1 or display == "none" or visibility == "hidden"

def detect_suspicious_iframes(
    raw_data: Dict[str, Any],
    domains: Tuple[str, ...] = DEFAULT_SUSPICIOUS_DOMAINS,
    large_threshold: Tuple[int, int] = (MIN_LARGE_WIDTH, MIN_LARGE_HEIGHT),
    tracker_threshold: Tuple[int, int] = (MAX_TRACKER_WIDTH, MAX_TRACKER_HEIGHT)
) -> Dict[str, Any]:
    """
    Analyze raw iframe entries and return any suspicious findings.

    Returns:
        {
            "suspicious_iframes_found": bool,
            "reasons": List[str]
        }
    """
    reasons: List[str] = []
    large_w, large_h = large_threshold
    max_tr_w, max_tr_h = tracker_threshold

    for idx, frame in enumerate(raw_data.get("iframes", []), start=1):
        width = _to_int(frame.get("width"))
        height = _to_int(frame.get("height"))
        opacity = _to_float(frame.get("opacity"))
        display = str(frame.get("display", "")).strip().lower()
        visibility = str(frame.get("visibility", "")).strip().lower()
        src = str(frame.get("src", "")).strip()
        sandbox = frame.get("sandbox")

        hidden = _is_hidden(opacity, display, visibility)
        large = width >= large_w and height >= large_h
        tracker = width <= max_tr_w and height <= max_tr_h
        external = any(domain in src.lower() for domain in domains)
        no_sandbox = sandbox is None

        frame_reasons: List[str] = []

        if hidden and external:
            if large:
                frame_reasons.append(
                    f"[#{idx}] Hidden large iframe from '{src}' ({width}×{height}, opacity={opacity})"
                )
            elif tracker and no_sandbox:
                frame_reasons.append(
                    f"[#{idx}] Tiny hidden tracker iframe at '{src}' without sandbox"
                )
            elif no_sandbox:
                frame_reasons.append(
                    f"[#{idx}] External iframe from '{src}' missing sandbox attribute"
                )

        for reason in frame_reasons:
            logger.debug("Detected suspicious iframe: %s", reason)
            reasons.append(reason)

    return {
        "suspicious_iframes_found": bool(reasons),
        "reasons": reasons
    }
