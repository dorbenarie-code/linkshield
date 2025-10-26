from typing import Any, Dict, List, Optional
from pathlib import Path
import html
import logging

# ----------------------------------------
# Configuration & Constants
# ----------------------------------------

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

STATUS_COLORS: Dict[str, str] = {
    "clean": "#2ecc71",
    "suspicious": "#f39c12",
    "malicious": "#e74c3c"
}

CSS_STYLES: str = """
body { font-family: Arial, sans-serif; margin: 2rem; }
.box { border: 1px solid #ccc; padding: 1.5rem; border-radius: 8px; max-width: 800px; }
.status { font-weight: bold; color: var(--status-color); }
.score  { font-weight: bold; color: var(--risk-color); }
.export-btn {
  display: inline-block; margin-top: 1rem; padding: 0.5rem 1rem;
  text-decoration: none; border: 1px solid #34495e; border-radius: 4px;
}
.screenshot img {
  max-width: 100%; border: 1px solid #ccc; border-radius: 4px;
}
.risk-bar-container {
  background-color: #eee; border-radius: 10px; height: 20px; width: 100%;
  margin-bottom: 1rem; overflow: hidden;
  box-shadow: inset 0 1px 3px rgba(0,0,0,0.2);
}
.risk-bar-fill { height: 100%; border-radius: 10px; transition: width 0.5s ease-in-out; }
"""

# ----------------------------------------
# Utility Layer
# ----------------------------------------

class HtmlUtils:
    """Helper methods for safe HTML generation."""

    @staticmethod
    def escape_value(value: Any) -> str:
        """Convert to str and escape HTML; returns empty string on failure."""
        try:
            return html.escape(str(value), quote=True)
        except Exception as e:
            logger.warning("escape_value failed for %r: %s", value, e)
            return ""

    @classmethod
    def format_reasons(cls, reasons: List[Any]) -> str:
        """Render reasons list as <li> items; show default if empty."""
        if not reasons:
            return "<li>No issues detected</li>"
        return "\n".join(f"<li>{cls.escape_value(r)}</li>" for r in reasons)

# ----------------------------------------
# Presentation Layer
# ----------------------------------------

class ReportComponents:
    """Builds individual HTML fragments for the report."""

    @staticmethod
    def build_screenshot_html(screenshot: Optional[str]) -> str:
        """Return screenshot section if path given; else empty."""
        if not screenshot:
            return ""
        path = HtmlUtils.escape_value(screenshot)
        return (
            '<div class="screenshot">\n'
            '  <h3>Screenshot</h3>\n'
            f'  <img src="file://{path}" alt="Screenshot"/>\n'
            '</div>\n'
        )

    @staticmethod
    def build_risk_bar(score: int) -> str:
        """Horizontal bar colored by risk; clamps score into [0,100]."""
        clamped = max(0, min(score, 100))
        color = ReportComponents.get_risk_color(clamped)
        return (
            '<div class="risk-bar-container">\n'
            f'  <div class="risk-bar-fill" style="width:{clamped}%; background-color:{color};"></div>\n'
            '</div>\n'
        )

    @staticmethod
    def get_status_color(status: str) -> str:
        """Fetch display color for status keyword, default gray."""
        return STATUS_COLORS.get(status.lower(), "#7f8c8d")

    @staticmethod
    def get_risk_color(score: int) -> str:
        """
        Determine risk color by score thresholds:
         - 0–30: clean (green)
         - 31–79: suspicious (orange)
         - 80–100: malicious (red)
        """
        if score <= 30:
            return STATUS_COLORS["clean"]
        if score < 80:
            return STATUS_COLORS["suspicious"]
        return STATUS_COLORS["malicious"]

    @staticmethod
    def get_css() -> str:
        """Return embedded CSS for the report."""
        return CSS_STYLES

# ----------------------------------------
# Main HTML Generator
# ----------------------------------------

def generate_html_content(data: Dict[str, Any]) -> str:
    """
    Generate the complete HTML content for a LinkShield scan report.

    - data["url"] or data["final_url"]: target URL
    - data["status"]: clean/suspicious/malicious
    - data["risk_score"]: integer 0–100
    - data["reasons"]: list of alert strings
    - data["screenshot"]: optional file path
    """
    # Safe extraction and conversion
    url    = HtmlUtils.escape_value(data.get("url") or data.get("final_url") or "-")
    status = HtmlUtils.escape_value(data.get("status") or "unknown")
    try:
        score = int(data.get("risk_score", 0))
    except Exception:
        score = 0

    # Set CSS custom properties for dynamic coloring
    css_vars = (
        f":root {{ "
        f"--status-color: {ReportComponents.get_status_color(status)}; "
        f"--risk-color:   {ReportComponents.get_risk_color(score)}; "
        f"}}\n"
    )
    css = css_vars + ReportComponents.get_css()

    # Assemble the HTML
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>🔍 LinkShield Scan Report</title>
  <style>{css}</style>
</head>
<body>
  <h1>🔍 LinkShield Scan Report</h1>
  <div class="box">
    <p><strong>URL:</strong> {url}</p>
    <p><strong>Status:</strong> 
      <span class="status">{status.title()}</span>
    </p>
    <p><strong>Risk Score:</strong> 
      <span class="score">{score}</span>
    </p>
    {ReportComponents.build_risk_bar(score)}
    <p><strong>Reasons:</strong></p>
    <ul>
      {HtmlUtils.format_reasons(data.get("reasons", []))}
    </ul>
    {ReportComponents.build_screenshot_html(data.get("screenshot"))}
    <a href="#" class="export-btn" onclick="alert('Export to PDF: TBD')">
      📄 Export as PDF
    </a>
  </div>
</body>
</html>"""
