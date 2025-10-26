from typing import Any, Dict, List, TypedDict

class SignalResult(TypedDict, total=False):
    reasons: List[str]
    meta: Dict[str, Any]

