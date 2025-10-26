#!/usr/bin/env python3
"""
Entry point to generate the LinkShield scan dashboard HTML.
"""
import sys
import logging
from pathlib import Path
from datetime import date

project_root = Path(__file__).resolve().parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from app.reports.renderers.summary_loader import load_tests_from_json
from app.reports.renderers.summary_stats import compute_summary
from app.reports.renderers.summary_renderer import render_summary_html
from app.reports.utils.report_utils import safe_write

logger = logging.getLogger(__name__)

# קבועים עבור הנתיב לקובץ JSON ותיקיית הפלט
DATA_FILE = Path("app/data/report_data.json")
OUTPUT_BASE = Path("reports")


def build_output_path(base_dir: Path, report_date: date) -> Path:
    """
    Construct the output HTML path for a given date:
      reports/YYYY-MM-DD/summary.html
    """
    return base_dir / report_date.isoformat() / "summary.html"


def generate_dashboard(json_path: Path, output_base: Path) -> None:
    """
    Load test data, compute stats, render HTML, and write to file.
    """
    tests = load_tests_from_json(json_path)
    if not tests:
        logger.error("No test data found at %s", json_path)
        return

    summary = compute_summary(tests)
    html = render_summary_html(tests, summary)

    output_path = build_output_path(output_base, date.today())
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        safe_write(output_path, html)
        logger.info("✅ Dashboard saved to: %s", output_path.resolve())
    except Exception as e:
        logger.error("Failed to save dashboard: %s", e)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s"
    )
    generate_dashboard(DATA_FILE, OUTPUT_BASE)


if __name__ == "__main__":
    main()
