# app/infra/browser_executor.py
from __future__ import annotations
import logging
import time
from typing import TYPE_CHECKING, Optional, List, Dict, Any, cast
from dataclasses import dataclass, asdict, field
from urllib.parse import urlparse
from playwright.sync_api import (
    sync_playwright,
    Playwright,
    Browser,
    TimeoutError as PlaywrightTimeoutError,
    Error as PlaywrightError
)

# ----- Runtime-safe imports with typing hints -----
try:
    # אם המודולים קיימים – הייבוא יעבוד; אם לא – ניפול ל-None בצורה בטוחה
    from app.scanner.signals.network_request_collector import NetworkRequestCollector  # type: ignore[reportMissingImports]
except Exception:
    NetworkRequestCollector = None  # type: ignore[assignment]

try:
    from app.scanner.signals.network_anomaly_signal import NetworkAnomalyDetector  # type: ignore[reportMissingImports]
except Exception:
    NetworkAnomalyDetector = None  # type: ignore[assignment]

if TYPE_CHECKING:
    # רק לצורכי טיפוס—לא ירוץ בזמן אמת
    from app.scanner.signals.network_request_collector import NetworkRequestCollector as _NRC  # type: ignore[reportMissingImports]
    from app.scanner.signals.network_anomaly_signal import NetworkAnomalyDetector as _NAD      # type: ignore[reportMissingImports]

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@dataclass
class PageResult:
    url: str
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    load_time_ms: Optional[int] = None
    redirects: List[str] = field(default_factory=list)
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    console_messages: List[Dict[str, Any]] = field(default_factory=list)
    iframes: List[Dict[str, Any]] = field(default_factory=list)
    screenshot: Optional[str] = None
    error: Optional[str] = None
    network_requests: List[Dict[str, Any]] = field(default_factory=list)
    network_analysis: Optional[Dict[str, Any]] = None


class BrowserExecutor:
    """
    Real browser executor using Playwright.
    Implements the Executor protocol from app.scanner.types.
    """
    
    def __init__(
        self,
        headless: bool = True,
        browser_type: str = 'chromium',
        timeout: int = 10000,
        viewport: Optional[object] = None,
        args: Optional[List[str]] = None
    ) -> None:
        self.headless = headless
        self.browser_type = browser_type
        self.timeout = timeout
        # Store viewport as None to avoid Playwright type issues
        self.viewport: Optional[object] = viewport
        self.args = args or []
        self._logger = logging.getLogger(self.__class__.__name__)
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None

    def __enter__(self) -> BrowserExecutor:
        """Context manager entry - starts Playwright and browser."""
        self._playwright = sync_playwright().start()
        launcher = getattr(self._playwright, self.browser_type)
        try:
            self._browser = launcher.launch(
                headless=self.headless,
                args=self.args
            )
        except PlaywrightError as e:
            raise RuntimeError(f"Failed to launch browser: {e}")
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit - closes browser and Playwright."""
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()

    def run_url(self, url: str, retries: int = 2) -> Dict[str, Any]:
        url = str(url).strip()
        result = PageResult(url=url)

        if not self._browser:
            raise RuntimeError("BrowserExecutor must be used as a context manager")

        for attempt in range(retries + 1):
            context = page = None
            try:
                start_time = time.time()
                # viewport: תן לברירת המחדל של Playwright; זה חוסך התראות טיפוסים
                context = self._browser.new_context()
                page = context.new_page()

                page.on("console", lambda msg: result.console_messages.append({
                    "type": msg.type,
                    "text": msg.text,
                    "location": msg.location
                }))

                if NetworkRequestCollector is None:
                    raise RuntimeError("NetworkRequestCollector module not available")
                collector = NetworkRequestCollector()  # type: ignore[operator]
                collector.attach(page)                 # type: ignore[attr-defined]

                response = page.goto(url, timeout=self.timeout, wait_until="networkidle")
                page.wait_for_timeout(2000)
                result.load_time_ms = int((time.time() - start_time) * 1000)

                requests_data: List[Dict[str, Any]] = collector.get_requests()  # type: ignore[attr-defined]
                result.network_requests = requests_data

                if NetworkAnomalyDetector is None:
                    raise RuntimeError("NetworkAnomalyDetector module not available")
                analyzer = NetworkAnomalyDetector()  # type: ignore[operator]
                all_reasons: List[str] = []
                # ודא ש-requests_data טיפוסי:
                requests_data = cast(List[Dict[str, Any]], requests_data)
                for req in requests_data:
                    req_url: str = cast(str, req.get("url", ""))
                    detection = analyzer.detect(req_url)  # type: ignore[attr-defined]
                    if detection.suspicious:  # type: ignore[attr-defined]
                        all_reasons.extend(detection.reasons)  # type: ignore[attr-defined]
                result.network_analysis = {
                    "suspicious_network_found": bool(all_reasons),
                    "reasons": all_reasons
                }
                print("🔎 Network analysis:", result.network_analysis)

                if response:
                    result.status_code = response.status
                    result.final_url = str(response.url)

                break

            except PlaywrightTimeoutError as e:
                logger.warning("Timeout for %s (attempt %d): %s", url, attempt, e)
                if attempt == retries:
                    result.error = f"Timeout after {retries + 1} attempts"
            except Exception as e:
                logger.exception("Error fetching %s: %s", url, e)
                result.error = str(e)
                break
            finally:
                if page:
                    page.close()
                if context:
                    context.close()

        return asdict(result)

    @staticmethod
    def _is_valid_url(url: str) -> bool:
        parsed = urlparse(str(url))
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)


class BrowserExecutionError(Exception):
    """Raised when browser execution fails unexpectedly."""
    pass
