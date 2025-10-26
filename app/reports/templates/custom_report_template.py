import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent))

import json
import html
import logging
import textwrap
from typing import TypedDict, Literal, Union, List, Dict

# Define allowed test statuses
Status = Literal["pass", "fail"]

# Define single test entry structure
class TestEntry(TypedDict):
    name: str
    status: Status

# Report data contains totals and list of tests
ReportData = Dict[str, Union[int, float, List[TestEntry]]]

# Logger config
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def validate_report_data(data: ReportData) -> None:
    """
    Confirm that data has all required fields with correct types,
    and warn if 'total' doesn't match number of tests.
    Raises:
      KeyError: missing required field
      TypeError: wrong type for a field
    """
    required = {"total", "passed", "failed", "duration", "tests"}
    missing = required - data.keys()
    if missing:
        raise KeyError(f"Missing required fields: {missing}")

    if not isinstance(data["tests"], list):
        raise TypeError(f"'tests' must be a list, got {type(data['tests']).__name__}")

    total = data["total"]
    if not isinstance(total, int):
        raise TypeError(f"'total' must be int, got {type(total).__name__}")

    if total != len(data["tests"]):
        logger.warning(
            "Field 'total' (%d) does not match number of tests (%d)",
            total, len(data["tests"])
        )

def format_test_rows(tests: List[TestEntry]) -> str:
    """
    Generate HTML table rows for each test entry.
    """
    symbols = {
        "pass": ("✅ Pass", "status-pass"),
        "fail": ("❌ Fail", "status-fail"),
    }
    rows = []
    for entry in tests:
        name = html.escape(entry["name"])
        status = entry["status"]
        symbol, css = symbols.get(status, ("❔ Unknown", "status-unknown"))
        rows.append(f'            <tr><td>{name}</td><td class="{css}">{symbol}</td></tr>')
    return "\n".join(rows)

def render_html(data: ReportData, timestamp: str, nonce: str) -> str:
    """
    Build a polished HTML report with visual charts and detailed test table.
    
    - data: report data including counts and individual test entries
    - timestamp: ISO-formatted generation time
    - nonce: CSP nonce for inline scripts/styles
    """
    # Extract summary metrics
    total = data.get("total", 0)
    passed = data.get("passed", 0)
    failed = data.get("failed", 0)
    duration = float(data.get("duration", 0.0))
    success_rate = round((passed / total * 100), 1) if total else 0.0

    # Build risk distribution buckets
    score_ranges = {"0–30": 0, "31–60": 0, "61–89": 0, "90–100": 0}
    for test in data.get("tests", []):
        score = int(test.get("risk_score", 0))
        if score <= 30:
            score_ranges["0–30"] += 1
        elif score <= 60:
            score_ranges["31–60"] += 1
        elif score <= 89:
            score_ranges["61–89"] += 1
        else:
            score_ranges["90–100"] += 1

    # Prepare JSON for charts
    labels_json      = json.dumps(["Passed", "Failed"])
    counts_json      = json.dumps([passed, failed])
    score_labels     = json.dumps(list(score_ranges.keys()))
    score_counts     = json.dumps(list(score_ranges.values()))
    esc_time         = html.escape(timestamp)

    # HTML head with Bootstrap + Chart.js and custom styles
    header = textwrap.dedent(f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta http-equiv="Content-Security-Policy"
            content="default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'nonce-{nonce}'; style-src 'self' https://cdn.jsdelivr.net;">
      <title>🔐 LinkShield Security Test Report</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
      <script src="https://cdn.jsdelivr.net/npm/chart.js" nonce="{nonce}"></script>
      <style nonce="{nonce}">
        body {{ background-color: #f0f2f5; }}
        h1, h3 {{ text-align: center; }}
        .metric {{ font-size: 1rem; }}
        .status-pass    {{ color: #28a745; font-weight: bold; }}
        .status-fail    {{ color: #dc3545; font-weight: bold; }}
        .status-unknown {{ color: #6c757d; font-style: italic; }}
        .chart-container {{ display: flex; justify-content: center; gap: 2rem; flex-wrap: wrap; margin: 2rem 0; }}
        canvas {{ background: #ffffff; padding: 1rem; border-radius: 0.5rem; box-shadow: 0 2px 6px rgba(0,0,0,0.1); }}
        .table-wrapper {{ overflow-x: auto; }}
      </style>
    </head>
    <body class="container my-4">
      <h1>🔐 LinkShield Security Test Report</h1>
      <div class="row text-center mb-4">
        <div class="col metric"><strong>Generated:</strong> {esc_time}</div>
        <div class="col metric"><strong>Duration:</strong> {duration:.2f}s</div>
        <div class="col metric"><strong>Success:</strong> {success_rate}%</div>
      </div>
      <div class="chart-container">
        <canvas id="resultChart" width="300" height="300"></canvas>
        <canvas id="scoreChart"  width="300" height="300"></canvas>
      </div>
      <script nonce="{nonce}">
        // Doughnut chart: pass vs fail
        new Chart(document.getElementById('resultChart'), {{
          type: 'doughnut',
          data: {{
            labels: {labels_json},
            datasets: [{{
              data: {counts_json},
              backgroundColor: ['#28a745', '#dc3545'],
              hoverOffset: 8
            }}]
          }},
          options: {{
            responsive: true,
            plugins: {{
              legend: {{ position: 'bottom' }},
              tooltip: {{ callbacks: {{ label: ctx => ctx.label + ': ' + ctx.parsed.toLocaleString() }} }}
            }}
          }}
        }});

        // Bar chart: risk distribution
        new Chart(document.getElementById('scoreChart'), {{
          type: 'bar',
          data: {{
            labels: {score_labels},
            datasets: [{{
              label: 'Number of Tests',
              data: {score_counts},
              backgroundColor: '#3498db',
              borderRadius: 4
            }}]
          }},
          options: {{
            responsive: true,
            scales: {{
              y: {{
                beginAtZero: true,
                ticks: {{ precision: 0 }}
              }}
            }},
            plugins: {{
              tooltip: {{ callbacks: {{ label: ctx => ctx.dataset.label + ': ' + ctx.parsed.y }} }}
            }}
          }}
        }});
      </script>

      <h3>🧪 Test Details</h3>
      <div class="table-wrapper">
        <table class="table table-hover">
          <thead class="table-secondary">
            <tr><th>Test Name</th><th>Status</th><th>Risk Score</th></tr>
          </thead>
          <tbody>
    """)

    # Build table rows
    rows = ""
    for test in data.get("tests", []):
        name = html.escape(test.get("name", "Unnamed Test"))
        status = test.get("status", "unknown").lower()
        score = test.get("risk_score", 0)
        css_class = f"status-{status}"
        rows += (
            f"<tr>"
            f"<td>{name}</td>"
            f"<td class='{css_class}'>{status.title()}</td>"
            f"<td>{score}</td>"
            f"</tr>\n"
        )

    footer = textwrap.dedent("""
          </tbody>
        </table>
      </div>
    </body>
    </html>
    """)

    return header + rows + footer
def safe_write(path: Path, content: str) -> None:
    """
    Validate path, create directories, and write safely with UTF-8.
    """
    if any(part == ".." for part in path.parts):
        raise ValueError("Unsafe path detected")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
