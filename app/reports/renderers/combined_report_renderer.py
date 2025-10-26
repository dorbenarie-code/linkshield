#!/usr/bin/env python3

# ----------------------------------------
# Project Root Setup (must be before imports)
# ----------------------------------------

import sys
from pathlib import Path

# Ensure project root is first on PYTHONPATH
project_root = Path(__file__).resolve().parents[1]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# ----------------------------------------
# Imports
# ----------------------------------------

import logging
import json
from datetime import datetime
from typing import List, Dict, Any

from app.utils.report_stats import summarize_tests
from utils.report_utils import safe_write


# ----------------------------------------
# Logger Configuration
# ----------------------------------------

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

# ----------------------------------------
# Constants (CSS & JS)
# ----------------------------------------

CSS_STYLES = """
:root {
  --clr-bg: #fafbfc;
  --clr-primary: #2c3e50;
  --clr-secondary: #34495e;
  --clr-accent: #3498db;
  --clr-low: #27ae60;
  --clr-med: #f1c40f;
  --clr-high: #e74c3c;
  --clr-text: #2d3e50;
  --clr-row-hover: #f0f3f5;
  --transition: 0.25s ease;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', sans-serif;
  background: var(--clr-bg);
  color: var(--clr-text);
  padding: 2rem;
  line-height: 1.5;
}
header, main, footer { max-width: 1200px; margin: 0 auto; }
header h1 {
  text-align: center;
  color: var(--clr-primary);
  margin-bottom: 1rem;
}
.stats { text-align: center; margin-bottom: 1.5rem; }
.chart-wrapper {
  max-width: 350px;
  margin: 0 auto 2rem;
  background: #fff;
  padding: 1rem;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  height: 300px;
}
nav.legend {
  display: flex;
  justify-content: center;
  gap: 1.5rem;
  margin-bottom: 2rem;
  font-size: 0.9rem;
}
.legend-item { display: flex; align-items: center; gap: 0.5rem; }
.legend-color {
  width: 14px; height: 14px; border-radius: 2px; display: inline-block;
}
.legend-color.low  { background: var(--clr-low); }
.legend-color.med  { background: var(--clr-med); }
.legend-color.high { background: var(--clr-high); }

.filter-container {
  text-align: center; margin-bottom: 1rem;
}
.filter-input {
  padding: 0.5rem;
  width: 100%; max-width: 400px;
  border: 1px solid var(--clr-secondary);
  border-radius: 4px;
  transition: border-color var(--transition);
}
.filter-input:focus {
  outline: none; border-color: var(--clr-accent);
}

table {
  width: 100%; border-collapse: collapse;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}
caption {
  caption-side: top; text-align: left;
  font-size: 1.1rem; margin-bottom: 0.5rem;
}
th, td { padding: 0.75rem 1rem; text-align: left; }
th {
  background: var(--clr-secondary);
  color: #fff; font-weight: 600;
}
tbody tr {
  background: #fff; transition: background var(--transition);
}
tbody tr:hover {
  background: var(--clr-row-hover);
}
.badge {
  display: inline-block;
  padding: 0.25rem 0.6rem;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 600;
  transition: transform var(--transition);
}
.badge:hover { transform: scale(1.05); }
.badge.clean      { background: var(--clr-low); }
.badge.suspicious { background: var(--clr-high); }

.progress-container {
  background: #e0e6eb;
  border-radius: 4px;
  overflow: hidden;
  height: 0.75rem;
  margin-bottom: 0.25rem;
}
.progress-bar {
  height: 100%; transition: width var(--transition);
}
.progress-bar.low  { background: var(--clr-low); }
.progress-bar.med  { background: var(--clr-med); }
.progress-bar.high { background: var(--clr-high); }
"""

JS_SCRIPTS = """
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
// Render the doughnut chart
function renderChart(passed, failed) {
  const ctx = document.getElementById("pieChart").getContext("2d");
  new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Passed", "Failed"],
      datasets: [{
        data: [passed, failed],
        backgroundColor: ["#27ae60","#e74c3c"],
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "bottom", labels: { boxWidth: 12 } }
      },
      aria: { enabled: true, label: 'Test results doughnut chart' }
    }
  });
}

// Table filter functionality
function filterTable() {
  const query = document.getElementById("filterInput").value.toLowerCase();
  document.querySelectorAll('tbody tr').forEach(tr => {
    const url = tr.querySelector('td.url').textContent.toLowerCase();
    tr.style.display = url.includes(query) ? "" : "none";
  });
}

document.addEventListener("DOMContentLoaded", () => {
  const passed = {{passed}}, failed = {{failed}};
  renderChart(passed, failed);
  document.getElementById("filterInput")
          .addEventListener("input", filterTable);
});
</script>
"""

# ----------------------------------------
# Data Loading Layer
# ----------------------------------------

def load_tests(json_path: Path) -> List[Dict[str, Any]]:
    """Load test entries from JSON; return empty list on error."""
    if not json_path.exists():
        logger.error(f"Test file not found: {json_path}")
        return []
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        return data.get("tests", [])
    except json.JSONDecodeError as e:
        logger.error(f"JSON parse error in {json_path}: {e}")
        return []

# ----------------------------------------
# HTML Rendering Layer
# ----------------------------------------

def render_table_rows(results: List[Dict[str, Any]]) -> str:
    """Generate HTML <tr> rows for each test."""
    rows = []
    for idx, entry in enumerate(results, start=1):
        url = entry.get("url", "-")
        status = entry.get("status", "unknown").title()
        badge_class = "clean" if status.lower() in ("clean", "ok") else "suspicious"
        risk = int(entry.get("risk_score", 0))
        bar_class = "low" if risk < 40 else "med" if risk < 70 else "high"
        html_link = entry.get("html_report", "#")
        pdf_link  = entry.get("pdf_report", "#")

        rows.append(f"""
<tr>
  <td>{idx}</td>
  <td class="url">{url}</td>
  <td><span class="badge {badge_class}">{status}</span></td>
  <td>
    <div class="progress-container">
      <div class="progress-bar {bar_class}" style="width:{risk}%"></div>
    </div>
    <span aria-label="Risk score">{risk}</span>
  </td>
  <td><a href="{html_link}" target="_blank" aria-label="View HTML report">🔍</a></td>
  <td><a href="{pdf_link}"  target="_blank" aria-label="View PDF report">📄</a></td>
</tr>""")
    return "\n".join(rows)

def render_summary_html(
    results: List[Dict[str, Any]],
    summary: Dict[str, Any]
) -> str:
    """Assemble full HTML document (header, stats, chart, legend, filter, table, footer)."""
    passed = summary.get("passed", 0)
    failed = summary.get("failed", 0)
    rows_html = render_table_rows(results)

    js = JS_SCRIPTS.replace("{{passed}}", str(passed)) \
                   .replace("{{failed}}", str(failed))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>LinkShield Scan Dashboard</title>
  {CSS_STYLES}
</head>
<body>
  <header>
    <h1>🔍 LinkShield Scan Dashboard</h1>
  </header>
  <main>
    <section class="stats" aria-label="Summary statistics">
      Total: {summary.get("total",0)} |
      Passed: {passed} |
      Failed: {failed} |
      Duration: {summary.get("duration",0)}s
    </section>
    <section class="chart-wrapper" aria-label="Results chart">
      <canvas id="pieChart" role="img" aria-label="Passed vs Failed"></canvas>
    </section>
    <nav class="legend" aria-label="Risk legend">
      <div class="legend-item"><span class="legend-color low"></span> Low</div>
      <div class="legend-item"><span class="legend-color med"></span> Medium</div>
      <div class="legend-item"><span class="legend-color high"></span> High</div>
    </nav>
    <div class="filter-container">
      <label for="filterInput">Filter URLs:</label>
      <input id="filterInput" class="filter-input" type="search" placeholder="Type to filter…" />
    </div>
    <table aria-describedby="table-caption">
      <caption id="table-caption">Scanned URLs and status</caption>
      <thead>
        <tr>
          <th scope="col">#</th>
          <th scope="col">URL</th>
          <th scope="col">Status</th>
          <th scope="col">Risk</th>
          <th scope="col">HTML</th>
          <th scope="col">PDF</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </main>
  <footer>
    <p style="text-align:center; padding:1rem 0; font-size:0.9rem; color:var(--clr-secondary);">
      Generated on {datetime.now().isoformat()}
    </p>
  </footer>
  {js}
</body>
</html>
"""

# ----------------------------------------
# Report Pipeline (Orchestration)
# ----------------------------------------

def render_combined_report(json_path: Path, output_path: Path) -> None:
    """Load tests, compute summary, render HTML, and save to disk."""
    tests = load_tests(json_path)
    if not tests:
        logger.warning("No tests found — generating empty dashboard.")

    summary = summarize_tests(tests)
    # Recompute passed/failed from status
    passed = sum(1 for t in tests if t.get("status","").lower() in ("clean","ok"))
    failed = len(tests) - passed
    summary["passed"], summary["failed"] = passed, failed

    html_content = render_summary_html(tests, summary)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        safe_write(output_path, html_content)
    except Exception as e:
        logger.error(f"Error writing report: {e}")
        return

    logger.info(f"✅ Dashboard saved to: {output_path}")

def main() -> None:
    """Entry point: determine file paths and run pipeline."""
    today = datetime.today().date().isoformat()
    json_path   = project_root / "results" / "report_data.json"
    output_path = project_root / "reports" / today / "summary.html"
    render_combined_report(json_path, output_path)

if __name__ == "__main__":
    main()
