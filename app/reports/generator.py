#!/usr/bin/env python3
import argparse
import json
import html
import logging
import webbrowser
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List
import secrets

from app.reports.renderers.html_report_renderer import generate_html_content
from app.reports.utils.report_utils import export_to_pdf, generate_screenshot, safe_path_under


from weasyprint import HTML
from scanner.link_scanner import LinkScanner
from tests.test_link_scanner_combined import StubExecutor  # FIXME: replace with BrowserExecutor when available
from PIL import Image, ImageDraw, ImageFont

ReportData = Dict[str, Any]

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Define base directory for reports
BASE_DIR = Path(__file__).parent.parent.resolve()

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a colored HTML scan report from JSON data or by scanning a URL."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="URL to scan (overrides JSON input)")
    group.add_argument("-j", "--json", type=Path, help="Path to existing JSON report data")
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=BASE_DIR / f"scan_report_{datetime.now():%Y%m%d_%H%M%S}.html",
        help="Output HTML file path"
    )
    return parser.parse_args()

def load_data_from_json(path: Path) -> ReportData:
    """Load existing report data from a JSON file."""
    return json.loads(path.read_text(encoding="utf-8"))

def scan_url(url: str) -> ReportData:
    """
    Run the scanner on the given URL, attach the most recent screenshot if available,
    or generate a new one using report_utils.generate_screenshot.
    Returns the scan result including the screenshot path.
    """
    screenshot_path = None
    try:
        # Look for any existing screenshots
        files = list(BASE_DIR.glob("screenshot_*.png"))
        if files:
            # Use the most recent existing screenshot
            screenshots = sorted(
                files,
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )
            screenshot_path = screenshots[0]
        else:
            # No existing screenshots → generate a new one safely
            # generate_screenshot will choose filename and ensure it's under the allowed directory
            screenshot_path = generate_screenshot("reports", text=url)
            # 📌 The above single call replaces manual filename construction
    except Exception as e:
        logger.warning(f"Screenshot lookup/generation failed: {e}")

    fake_data = {
        "final_url": url,
        "status": "clean",
        "risk_score": 5,
        "reasons": [],
        "url": url,
        "screenshot": str(screenshot_path) if screenshot_path else None
    }

    scanner = LinkScanner(StubExecutor(fake_data))
    return scanner.scan(url)

def get_status_color(status: str) -> str:
    base = {"clean": "#2ecc71", "suspicious": "#f39c12", "malicious": "#e74c3c"}
    return base.get(status, "#7f8c8d")

def get_risk_color(score: int) -> str:
    if score <= 30:
        return "#2ecc71"
    if score < 80:
        return "#f39c12"
    return "#e74c3c"

def _escape(text: Any) -> str:
    """Escape input to prevent HTML injection."""
    return html.escape(str(text or ""))

def _format_reasons(reasons: List[str]) -> str:
    """Render an HTML list of reasons, or a default message if none."""
    if not reasons:
        return "<li>No issues detected</li>"
    return "\n".join(f"<li>{_escape(r)}</li>" for r in reasons)

def _build_screenshot_html(path_str: Any) -> str:
    """
    Embed a screenshot if the file exists and is in a supported image format.
    """
    if not path_str:
        return ""
    try:
        path = Path(str(path_str))
        abs_path = path.resolve(strict=True)
        if abs_path.suffix.lower() not in {".png", ".jpg", ".jpeg", ".gif", ".bmp"}:
            logger.warning(f"Unsupported screenshot format: {abs_path.suffix}")
            return ""
        return f"""
        <div class="screenshot">
          <h3>Screenshot</h3>
          <img src="{abs_path.as_uri()}" alt="Screenshot"/>
        </div>
        """
    except Exception as e:
        logger.error(f"Failed to embed screenshot: {e}")
        return ""

def write_report(html_content: str, path: Path) -> None:
    """Write out the HTML report, creating directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_content, encoding="utf-8")
    print(f"✅ Report generated at: {path.resolve()}")

def main():
    args = parse_args()

    if args.url:
        data = scan_url(args.url)
    else:
        data = load_data_from_json(args.json)

    html_content = generate_html_content(data)
    write_report(html_content, args.output)

    pdf_path = args.output.with_suffix(".pdf")
    data["output_pdf"] = pdf_path.name
    export_to_pdf(args.output, pdf_path)

    webbrowser.open(args.output.resolve().as_uri())

if __name__ == "__main__":
    main()
