#!/usr/bin/env python3
import argparse
import json
import html
import logging
import webbrowser
import secrets
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List

from weasyprint import HTML
from PIL import Image, ImageDraw, ImageFont

from scanner.link_scanner import LinkScanner
from tests.test_link_scanner_combined import StubExecutor  # FIXME: replace with BrowserExecutor when available

ReportData = Dict[str, Any]

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

# Only allow files under this directory
BASE_DIR = Path("reports").resolve()

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

def _safe_path(path: Path) -> Path:
    """
    Ensure the given path is inside BASE_DIR to prevent directory traversal.
    """
    candidate = path.resolve()
    if BASE_DIR not in candidate.parents and candidate != BASE_DIR:
        raise ValueError(f"Invalid path: {candidate} is outside of {BASE_DIR}")
    return candidate

def export_to_pdf(html_path: Path, pdf_path: Path) -> None:
    """
    Convert an HTML report to PDF and save it.
    """
    try:
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        print(f"📄 PDF exported to: {pdf_path.resolve()}")
    except Exception as e:
        logger.error(f"❌ Failed to export PDF: {e}")

def generate_screenshot(path: Path, text: str = "LinkShield Test Screenshot") -> None:
    """
    Create a 600×300 PNG image with centered text, random background and noise,
    then save it under reports/. Raises if path is outside BASE_DIR.
    """
    # Determine and validate output path
    path = path if not path.is_dir() else BASE_DIR / f"screenshot_{secrets.token_hex(8)}.png"
    path = _safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    width, height = 600, 300
    # Random background color
    bg_color = (
        secrets.randbelow(256),
        secrets.randbelow(256),
        secrets.randbelow(256)
    )
    image = Image.new("RGB", (width, height), color=bg_color)
    draw = ImageDraw.Draw(image)

    # Load a font (fallback to default)
    try:
        font = ImageFont.truetype("arial.ttf", 24)
    except Exception:
        font = ImageFont.load_default()

    # Measure text bbox and apply a small random shift
    bbox = draw.textbbox((0, 0), text, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]
    shift_x = secrets.randbelow(11) - 5
    shift_y = secrets.randbelow(11) - 5
    pos = ((width - text_w) // 2 + shift_x, (height - text_h) // 2 + shift_y)

    # Draw contrasting text
    text_color = tuple(255 - c for c in bg_color)
    draw.text(pos, text, fill=text_color, font=font)

    # Add random noise points
    for _ in range(100):
        x = secrets.randbelow(width)
        y = secrets.randbelow(height)
        noise = (
            secrets.randbelow(256),
            secrets.randbelow(256),
            secrets.randbelow(256)
        )
        draw.point((x, y), fill=noise)

    # Save optimized PNG
    image.save(path, optimize=True)
    logger.info(f"✅ Dummy screenshot saved to: {path}")
    print(f"✅ Dummy screenshot saved to: {path.resolve()}")

# ------------------------------------------------------------------------------
# Core functionality
# ------------------------------------------------------------------------------

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
        default=Path(f"reports/scan_report_{datetime.now():%Y%m%d_%H%M%S}.html"),
        help="Output HTML file path"
    )
    return parser.parse_args()

def load_data_from_json(path: Path) -> ReportData:
    """Load existing report data from a JSON file."""
    return json.loads(path.read_text(encoding="utf-8"))

def scan_url(url: str) -> ReportData:
    """
    Run the scanner on the given URL, generate a dummy screenshot,
    and return the result dict including the screenshot path.
    """
    # Generate a unique screenshot under reports/
    screenshot_name = f"screenshot_{secrets.token_hex(8)}.png"
    screenshot_path = BASE_DIR / screenshot_name
    generate_screenshot(screenshot_path, text=url)

    fake_data = {
        "final_url": url,
        "status": "clean",
        "risk_score": 5,
        "reasons": [],
        "url": url,
        "screenshot": str(screenshot_path)
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

# ─── Helpers for HTML generation ───────────────────────────────────────────

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
    Embed a screenshot if the file exists and is a supported image format.
    """
    try:
        path = Path(str(path_str))
        abs_path = path.resolve(strict=True)
        if abs_path.suffix.lower() not in {".png", ".jpg", ".jpeg", ".gif", ".bmp"}:
            logger.warning(f"Unsupported screenshot format: {abs_path.suffix}")
            return ""
        return f"""
        <div class="screenshot">
          <h3>Screenshot</h3>
          <img src="file://{_escape(abs_path)}" alt="Screenshot"/>
        </div>
        """
    except Exception as e:
        logger.error(f"Failed to embed screenshot: {e}")
        return ""

def generate_html_content(data: ReportData) -> str:
    """
    Build the full HTML report, including styles, content, screenshot,
    PDF export button and a download link for the generated PDF.
    """
    # 1. Extract fields safely
    url = _escape(data.get("url") or data.get("final_url") or "-")
    status = _escape(data.get("status") or "unknown")
    try:
        score = int(data.get("risk_score", 0))
    except (TypeError, ValueError):
        score = 0

    # 2. Determine colors
    status_color = get_status_color(status)
    risk_color = get_risk_color(score)

    # 3. Prepare list and screenshot HTML
    reasons_html = _format_reasons(data.get("reasons", []))
    screenshot_html = _build_screenshot_html(data.get("screenshot"))

    # 3.1 PDF download link (filename only)
    pdf_filename = _escape(data.get("output_pdf", "scan_report.pdf"))
    pdf_link = f'<a href="{pdf_filename}" class="export-btn" download>⬇️ Download PDF</a>'

    # 4. CSS styles
    css = f"""
    body {{ font-family: Arial, sans-serif; margin: 2rem; }}
    .box {{ border: 1px solid #ccc; padding: 1.5rem; border-radius: 8px; max-width: 800px; }}
    .status {{ font-weight: bold; color: {status_color}; }}
    .score  {{ font-weight: bold; color: {risk_color}; }}
    .export-btn {{
      display: inline-block; margin-top: 1rem; padding: 0.5rem 1rem;
      text-decoration: none; border: 1px solid #34495e; border-radius: 4px;
    }}
    .screenshot img {{ max-width: 100%; border: 1px solid #ccc; border-radius: 4px; }}
    """

    # 5. Assemble HTML
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>LinkShield Scan Report</title>
  <style>{css}</style>
</head>
<body>
  <h1>🔍 LinkShield Scan Report</h1>
  <div class="box">
    <p><strong>URL:</strong> {url}</p>
    <p><strong>Status:</strong> <span class="status">{status}</span></p>
    <p><strong>Risk Score:</strong> <span class="score">{score}</span></p>

    <p><strong>Reasons:</strong></p>
    <ul>{reasons_html}</ul>
    {screenshot_html}

    <!-- Export buttons -->
    <a href="#" class="export-btn" onclick="alert('Export to PDF: TBD')">
      📄 Export as PDF
    </a>
    {pdf_link}
  </div>
</body>
</html>"""

def write_report(html_content: str, path: Path) -> None:
    """
    Write out the HTML report, creating directories if needed.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_content, encoding="utf-8")
    print(f"✅ Report generated at: {path.resolve()}")

def main():
    args = parse_args()

    # Acquire data via scan or JSON input
    if args.url:
        data = scan_url(args.url)
    else:
        data = load_data_from_json(args.json)

    # Generate and write HTML report
    html_content = generate_html_content(data)
    write_report(html_content, args.output)

    # Generate PDF and store its filename for linking
    pdf_path = args.output.with_suffix(".pdf")
    data["output_pdf"] = pdf_path.name
    export_to_pdf(args.output, pdf_path)

    # Open the HTML report in the default browser
    webbrowser.open(args.output.resolve().as_uri())

if __name__ == "__main__":
    main()
