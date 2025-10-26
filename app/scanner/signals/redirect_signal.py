"""Redirect signal: מזהה ריבוי רידיירקטים. מחזיר reasons + meta."""
from typing import Any
from app.scanner.signals.types import SignalResult

def detect_redirects(result: Any, threshold: int = 2) -> SignalResult:
    """Unified format: reasons + meta; reason string remains identical."""
    # Support both dict and object with attributes
    if isinstance(result, dict):
        chain = (
            result.get("redirects")
            or result.get("redirect_chain")
            or result.get("history")
            or []
        )
    else:
        chain = (
            getattr(result, "redirects", None)
            or getattr(result, "redirect_chain", None)
            or getattr(result, "history", None)
            or []
        )
    try:
        count = len(chain)
    except TypeError:
        count = 0
    reasons = ["Multiple redirects detected"] if count >= threshold else []
    return {"reasons": reasons, "meta": {"count": count, "threshold": threshold}}

def has_multiple_redirects(result: Any, threshold: int = 2) -> bool:
    """Backward compatibility shim."""
    return bool(detect_redirects(result, threshold=threshold).get("reasons"))

