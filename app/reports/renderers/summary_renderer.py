# app/reports/renderers/summary_renderer.py

"""
Summary Renderer Module

Generates the HTML dashboard and table rows
for LinkShield scan results, and saves the report to disk.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Union
from app.reports.renderers.summary_assets import CSS_STYLES, JS_SCRIPTS

# —————————————————————————————————————————————————————————————————————————————
# Logger
# —————————————————————————————————————————————————————————————————————————————
logger = logging.getLogger(__name__)

# —————————————————————————————————————————————————————————————————————————————
# Type Aliases
# —————————————————————————————————————————————————————————————————————————————
Result = Dict[str, Any]
Results = List[Result]
Summary = Dict[str, Any]


# —————————————————————————————————————————————————————————————————————————————
# Helper Functions
# —————————————————————————————————————————————————————————————————————————————
def _badge_class(status: str) -> str:
    """
    Return the CSS class for status badges.
    'clean' if status is 'clean' (case-insensitive), otherwise 'suspicious'.
    """
    return "clean" if status.lower() == "clean" else "suspicious"


def _progress_class(score: int) -> str:
    """
    Return the CSS class for the progress bar.
    - score < 40 → 'low'
    - score < 70 → 'med'
    - otherwise → 'high'
    """
    if score < 40:
        return "low"
    if score < 70:
        return "med"
    return "high"


# —————————————————————————————————————————————————————————————————————————————
# Row Renderer
# —————————————————————————————————————————————————————————————————————————————
def render_table_rows(results: Results) -> str:
    """
    Build HTML <tr> rows for each scan result.

    Columns:
      1. Index
      2. URL
      3. Status badge
      4. Risk bar + numeric score
      5. Link to HTML report
      6. Link to PDF report
    """
    rows: List[str] = []

    for idx, entry in enumerate(results, start=1):
        url           = entry.get("url", "-")
        raw_status    = entry.get("status", "unknown")
        status_text   = raw_status.title()
        badge_cls     = _badge_class(raw_status)
        risk_score    = int(entry.get("risk_score", 0))
        progress_cls  = _progress_class(risk_score)
        html_report   = entry.get("html_report", "#")
        pdf_report    = entry.get("pdf_report", "#")

        rows.append(f"""
<tr>
  <td>{idx}</td>
  <td class=\"url\">{url}</td>
  <td><span class=\"badge {badge_cls}\">{status_text}</span></td>
  <td>
    <div class=\"progress-container\">
      <div class=\"progress-bar {progress_cls}\" style=\"width:{risk_score}%\"></div>
    </div>
    <span aria-label=\"Risk score\">{risk_score}</span>
  </td>
  <td><a href=\"{html_report}\" target=\"_blank\">🔍</a></td>
  <td><a href=\"{pdf_report}\"  target=\"_blank\">📄</a></td>
</tr>""")

    return "\n".join(rows)


# —————————————————————————————————————————————————————————————————————————————
# Main Renderer
# —————————————————————————————————————————————————————————————————————————————
def render_summary_html(results: Results, summary: Summary) -> str:
    """
    Build the complete HTML page for the LinkShield dashboard.

    Injects:
      • CSS styles (from CSS_STYLES)
      • JS scripts (from JS_SCRIPTS, with passed/failed counts)
      • Summary stats (total/passed/failed/duration)
      • Table rows (using render_table_rows)
    """
    total    = summary.get("total", 0)
    passed   = summary.get("passed", 0)
    failed   = summary.get("failed", 0)
    duration = summary.get("duration", 0.0)

    rows_html = render_table_rows(results)

    # Inject dynamic values into the JS snippet
    js_snippet = (
        JS_SCRIPTS
        .replace("{{passed}}", str(passed))
        .replace("{{failed}}",  str(failed))
    )

    # Assemble the final HTML
    return (
        f"<!DOCTYPE html>\n"
        f"<html lang=\"en\">\n"
        f"<head>\n"
        f"  <meta charset=\"UTF-8\"/>\n"
        f"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"/>\n"
        f"  <title>LinkShield Scan Dashboard</title>\n"
        f"  <style>{CSS_STYLES}</style>\n"
        f"</head>\n"
        f"<body>\n"
        f"  <header>\n"
        f"    <h1>🔍 LinkShield Scan Dashboard</h1>\n"
        f"  </header>\n"
        f"  <main>\n"
        f"    <section class=\"stats\">\n"
        f"      Total: {total} | Passed: {passed} | Failed: {failed} | Duration: {duration}s\n"
        f"    </section>\n"
        f"    <section class=\"chart-wrapper\">\n"
        f"      <canvas id=\"pieChart\"></canvas>\n"
        f"    </section>\n"
        f"    <div class=\"filter-container\">\n"
        f"      <label for=\"filterInput\">Filter URLs:</label>\n"
        f"      <input id=\"filterInput\" class=\"filter-input\" type=\"search\" placeholder=\"Type to filter…\" />\n"
        f"    </div>\n"
        f"    <table>\n"
        f"      <thead>\n"
        f"        <tr>\n"
        f"          <th>#</th><th>URL</th><th>Status</th><th>Risk</th><th>HTML</th><th>PDF</th>\n"
        f"        </tr>\n"
        f"      </thead>\n"
        f"      <tbody>\n"
        f"{rows_html}\n"
        f"      </tbody>\n"
        f"    </table>\n"
        f"  </main>\n"
        f"  <footer>\n"
        f"    <p style=\"text-align:center; padding:1rem; color:#999;\">\n"
        f"      Generated on {datetime.now().isoformat()}\n"
        f"    </p>\n"
        f"  </footer>\n"
        f"  {js_snippet}\n"
        f"</body>\n"
        f"</html>"
    )


# —————————————————————————————————————————————————————————————————————————————
# Report Saving Utility
# —————————————————————————————————————————————————————————————————————————————
def save_summary_report(
    results: Results,
    summary: Summary,
    output_path: Union[str, Path]
) -> Path:
    """
    Render and save the summary HTML dashboard to disk.

    Args:
        results: A list of individual scan results.
        summary: Aggregated summary statistics.
        output_path: File path where the HTML will be saved.

    Returns:
        The Path object of the saved report.
    """
    path = Path(output_path)
    try:
        html = render_summary_html(results, summary)
        # Ensure target directory exists
        path.parent.mkdir(parents=True, exist_ok=True)
        # Write the HTML file
        path.write_text(html, encoding="utf-8")
        # Log with file name and entry count
        logger.info(
            "✅ Summary report saved to: %s (%d entries)",
            path,
            len(results)
        )
        return path
    except Exception as e:
        logger.error("Failed to save summary report: %s", e, exc_info=True)
        raise
