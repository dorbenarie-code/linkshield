from __future__ import annotations
import re
from typing import Any, Dict, List, Iterable, Tuple

_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("eval\\(", re.compile(r"eval\(", re.IGNORECASE)),
    ("new Function\\(", re.compile(r"new\s+function\s*\(", re.IGNORECASE)),
    ("crypto\\.subtle", re.compile(r"crypto\.subtle", re.IGNORECASE)),
    ("document\\.write\\(", re.compile(r"document\.write\s*\(", re.IGNORECASE)),
    ("atob\\(", re.compile(r"atob\s*\(", re.IGNORECASE)),
    ("btoa\\(", re.compile(r"btoa\s*\(", re.IGNORECASE)),
    ("fingerprint", re.compile(r"fingerprint", re.IGNORECASE)),  # html only
]

def _as_list(x: Any) -> List[str]:
    if x is None:
        return []
    if isinstance(x, list):
        return [str(v) for v in x if v is not None]
    if isinstance(x, str):
        return [x]
    return []

class JSBehaviorSignal:
    def __init__(self) -> None:
        self.patterns = _PATTERNS

    def detect(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        console = _as_list(raw.get("console_messages"))
        html = str(raw.get("html", "") or "")
        js_raw_list = _as_list(raw.get("js_raw"))

        matched: List[str] = []
        match_count = 0

        # per-entry de-duplication: לכל רשומה סופרים לכל היותר דפוס אחד
        for entry in console:
            if self._match_any(entry, matched):
                match_count += 1
        if html:
            if self._match_any(html, matched):
                match_count += 1
        for entry in js_raw_list:
            if self._match_any(entry, matched):
                match_count += 1

        return {
            "suspicious_js_found": match_count > 0,
            "alerts": ["Suspicious JS behavior"] * (1 if match_count > 0 else 0),
            "match_count": match_count,
            "matched_patterns": matched,       # תמיד עם תבניות escaped
            "console_entries": console,
            "html_entries": [html] if html else [],
            "js_raw_entries": js_raw_list,
        }

    def _match_any(self, text: str, acc: List[str]) -> bool:
        for esc, rx in self.patterns:
            if rx.search(text):
                # הוסף רק את התבנית (escaped) – לא את הטקסט הגולמי
                if esc not in acc:
                    acc.append(esc)
                return True  # סופרים לכל היותר פעם אחת פר רשומה
        return False

def detect_js_behaviors(raw: Dict[str, Any]) -> Dict[str, Any]:
    return JSBehaviorSignal().detect(raw)
