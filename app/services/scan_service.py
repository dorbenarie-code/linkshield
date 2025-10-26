from __future__ import annotations
from typing import Any, Dict, Optional, Protocol, runtime_checkable
from urllib.parse import urlparse
# ה-import עובד בזמן ריצה, אבל ה-linter לפעמים לא מזהה את הנתיב – משתיקים רק סטטית:
from app.scanner.exceptions import ScanError  # type: ignore[reportMissingImports]

class ScanResult(Dict[str, Any]):
    """alias טיפוסי נוח לתשובת הסריקה"""
    pass

@runtime_checkable
class ExecutorProtocol(Protocol):
    def __init__(self, timeout: Optional[int] = None) -> None: ...
    def __enter__(self) -> "ExecutorProtocol": ...
    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None: ...
    def run_url(self, url: str) -> Dict[str, Any]: ...

class ScanService:
    def __init__(self, executor_cls: type[ExecutorProtocol], timeout: Optional[int] = None) -> None:
        self.executor_cls: type[ExecutorProtocol] = executor_cls
        self.timeout = timeout

    def _validate_url(self, url: str) -> None:
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            raise ValueError("Invalid URL")

    def run(self, url: str) -> ScanResult:
        self._validate_url(url)
        try:
            with self.executor_cls(timeout=self.timeout) as ex:  # type: ignore[call-arg]
                # לפי הטסטים – מחזירים את מה שה-executor מחזיר אחד-לאחד
                res: Dict[str, Any] = ex.run_url(url)
                return ScanResult(res)
        except Exception as e:
            # לפי הטסט – יש לעטוף כשלה של executor ל-ScanError
            raise ScanError(str(e))
