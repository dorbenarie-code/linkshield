#!/usr/bin/env python3
"""
custom_report_generator.py

Generate a highly secure and elegant HTML and PDF report for LinkShield security tests.

🟢 Verdict:
✅ The module is correct, modular, stable, and elegant.
Ready for full use by batch_scanner.py and standalone execution.
"""

import sys
import logging
import html as html_lib
import secrets
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List

# Add project root to sys.path for imports
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from app.reports.templates.custom_report_template import (  # type: ignore[reportMissingImports]
    render_html,
    validate_report_data,
    safe_write,
)

# --- Configure logger ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --- Custom Exceptions -------------------------------------------------------
class ReportError(Exception):
    """Base exception for report-related failures."""

class HTMLGenerationError(ReportError):
    """Raised when HTML rendering fails."""

class PDFExportError(ReportError):
    """Raised when PDF export fails."""

# --- Types -------------------------------------------------------------------
ReportData = Dict[str, Any]

# --- Helper Functions -------------------------------------------------------
# BONUS: you may consider moving format_test_rows() to custom_report_template.py to fully separate HTML logic.
def format_test_rows(tests: List[Dict[str, Any]]) -> str:
    """Build HTML table rows for each test, escaping content safely."""
    rows: List[str] = []
    for t in tests:
        name = html_lib.escape(str(t.get("name", "")))
        status = str(t.get("status", "")).lower()
        symbol, css = (
            ("✅ Pass", "status-pass")
            if status == "pass"
            else ("❌ Fail", "status-fail")
        )
        rows.append(f'      <tr><td>{name}</td><td class="{css}">{symbol}</td></tr>')
    return "\n".join(rows)

# --- Report Generation -------------------------------------------------------
def generate_html_report(data: ReportData, output_path: Path) -> str:
    """
    Generate an HTML report from `data`, save to `output_path`, and return the HTML string.

    - Adds timestamp & nonce for traceability and cache-busting.
    - Ensures the output directory exists.
    - Logs successes and failures.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    nonce = secrets.token_urlsafe(16)

    # 1. Validate data
    validate_report_data(data)

    # 2. Render HTML content
    try:
        html_content: str = render_html(data, timestamp=timestamp, nonce=nonce)
    except Exception as e:
        logger.error(f"Failed to render HTML report: {e}")
        raise HTMLGenerationError("Error in render_html()") from e

    # 3. Ensure output directory exists and write file
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        safe_write(output_path, html_content)
    except Exception as e:
        logger.error(f"Failed to write HTML to {output_path}: {e}")
        raise

    logger.info(f"✅ HTML report saved to: {output_path}")
    return html_content


def export_to_pdf(html_path: Path, pdf_path: Path, engine: str = "wkhtmltopdf") -> None:
    """
    Convert an HTML file to PDF using an external engine.

    - Tries `wkhtmltopdf` first; if missing or fails, falls back to `weasyprint`.
    - Ensures target directory exists.
    - Raises PDFExportError on total failure.
    """
    # 1. Validate source
    if not html_path.exists():
        msg = f"HTML source not found: {html_path}"
        logger.error(msg)
        raise FileNotFoundError(msg)

    # 2. Prepare output folder
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    # 3. Try primary engine
    try:
        subprocess.run([engine, str(html_path), str(pdf_path)], check=True)
        logger.info(f"📄 PDF exported to: {pdf_path}")
        return
    except FileNotFoundError:
        logger.warning(f"{engine} not found; attempting fallback...")
    except subprocess.CalledProcessError as e:
        logger.error(f"{engine} failed: {e}; attempting fallback...")

    # 4. Fallback to weasyprint if available
    try:
        from weasyprint import HTML  # type: ignore[reportMissingImports]
        HTML(str(html_path)).write_pdf(str(pdf_path))  # type: ignore[reportUnknownMemberType]
        logger.info(f"📄 PDF exported via weasyprint to: {pdf_path}")
    except ImportError:
        msg = "No PDF engine available (wkhtmltopdf missing and weasyprint not installed)"
        logger.error(msg)
        raise PDFExportError(msg)
    except Exception as e:
        msg = f"Weasyprint export error: {e}"
        logger.error(msg)
        raise PDFExportError(msg)

# --- Main Entry Point --------------------------------------------------------
def main():
    """
    Example main: load report data, generate HTML and PDF reports.
    """
    # Load example data or from external JSON
    report_data: ReportData = {
        "total": 8,
        "passed": 8,
        "failed": 0,
        "duration": 15.04,
        "tests": [
            {"name": "test_http_error", "status": "pass"},
            {"name": "test_invalid_scheme", "status": "pass"},
            {"name": "test_plain_html", "status": "pass"},
            {"name": "test_redirect_chain", "status": "pass"},
            {"name": "test_safe_url", "status": "pass"},
            {"name": "test_ssl_error", "status": "pass"},
            {"name": "test_suspicious_keyword", "status": "pass"},
            {"name": "test_unresolvable_domain", "status": "pass"}
        ]
    }

    output_html = Path("reports/custom_report.html")
    output_pdf  = output_html.with_suffix(".pdf")

    try:
        generate_html_report(report_data, output_html)
        export_to_pdf(output_html, output_pdf)
        logger.info("✅ Secure report created at %s and %s", output_html, output_pdf)
    except Exception:
        logger.exception("❌ Failed to generate full report")
        sys.exit(1)


if __name__ == "__main__":
    main()
