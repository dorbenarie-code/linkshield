from typing import Any

def has_multiple_redirects(result: Any, threshold: int = 2) -> bool:
    """
    Returns True if the number of redirects >= threshold.
    Works with fields named redirects/redirect_chain/history, or None.
    No behavioral change - only extracts logic to a module.
    """
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
        return len(chain) >= threshold
    except TypeError:
        return False

