#!/usr/bin/env python3

import sys
import os
import argparse
import json
import logging
import secrets
import webbrowser
import subprocess

from datetime import datetime, date
from pathlib import Path
from typing import Any, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

# project root on sys.path for local imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from app.utils.report_stats import summarize_tests
from app.utils.mail_utils import send_report_email
from app.services.scan_service import ScanService
from app.scanner.exceptions import ScanError
from app.reports.templates.custom_report_template import render_html, validate_report_data
from app.reports.renderers.summary_renderer import render_summary_html
from app.reports.utils.report_utils import safe_write


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

ReportData = Dict[str, Any]


def is_wsl_environment() -> bool:
    """Detect if running inside Windows Subsystem for Linux (WSL)."""
    try:
        with open("/proc/version", "r") as f:
            return "microsoft" in f.read().lower()
    except Exception:
        return False


def open_report(path: Path) -> None:
    """
    Open the report in the default browser.
    Converts path using wslpath if running in WSL.
    """
    try:
        if is_wsl_environment():
            result = subprocess.run(
                ["wslpath", "-w", str(path.resolve())],
                capture_output=True, text=True
            )
            win_path = result.stdout.strip()
            subprocess.run(["cmd.exe", "/c", "start", "", win_path])
        else:
            webbrowser.open(str(path.resolve()))
        logging.info("🌐 Opened report in browser")
    except Exception as e:
        logging.error("❌ Failed to open report: %s", e)


def load_all_scan_results(path: Path = Path("results/report_data.json")) -> List[Dict[str, Any]]:
    """
    Load and return the 'tests' array from a scan-results JSON file.

    Args:
        path (Path): Path to the JSON file containing scan results.

    Returns:
        List[Dict[str, Any]]: A list of test-result dictionaries.
    """
    path = path if isinstance(path, Path) else Path(path)

    if not path.exists():
        raise FileNotFoundError(f"❌ File not found at: {path}")

    content = path.read_text(encoding="utf-8")
    data = json.loads(content)

    if "tests" not in data or not isinstance(data["tests"], list):
        raise ValueError("❌ JSON must contain a list under 'tests'")

    return data["tests"]


def generate_fresh_scan_data(
    urls: List[str],
    output_path: Path,
    timeout_ms: int = 15000,
    max_workers: int = 4
) -> None:
    """
    Perform live scans on the provided URLs in parallel and write structured results to JSON.

    :param urls: list of URLs to scan
    :param output_path: path to write report_data.json
    :param timeout_ms: per-scan timeout in milliseconds
    :param max_workers: number of threads for parallel scanning
    """
    service = ScanService(timeout=timeout_ms)
    results: List[Dict[str, Any]] = []

    def _scan_one(u: str) -> Dict[str, Any]:
        try:
            return service.run(u)
        except ScanError as se:
            logging.error(f"ScanError for {u}: {se}")
            return {"url": u, "status": "error", "reason": str(se)}
        except Exception:
            logging.exception(f"Unexpected error for {u}")
            return {"url": u, "status": "error", "reason": "Unexpected exception"}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(_scan_one, url): url for url in urls}
        for future in as_completed(future_to_url):
            results.append(future.result())

    payload = {"tests": results}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    logging.info(f"Generated fresh scan data at {output_path.resolve()}")


def parse_args() -> argparse.Namespace:
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate a secure HTML report from a JSON data file."
    )
    parser.add_argument(
        "json_path",
        type=Path,
        help="Path to the input JSON report file (or 'generate' to produce fresh data)."
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("reports/custom_report.html"),
        help="Optional output HTML file path (default: reports/custom_report.html)"
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Automatically open the generated report in the default web browser."
    )
    return parser.parse_args()


def load_and_validate(path: Path) -> ReportData:
    """Load JSON data and validate its structure using custom template validation."""
    if not path.exists():
        logging.error("Report file not found: %s", path)
        sys.exit(1)
    if path.suffix.lower() != ".json":
        logging.error("Invalid file extension: %s (only .json allowed)", path.suffix)
        sys.exit(1)

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        logging.error("Failed to parse JSON: %s", e)
        sys.exit(1)

    try:
        validate_report_data(data)
    except Exception as e:
        logging.error("Report data validation failed: %s", e)
        sys.exit(1)

    return data


def main() -> None:
    args = parse_args()

    if args.json_path.name == "generate":
        urls_to_scan = [
            "https://example.com",
            "https://expired.badssl.com",
            "https://accounts.google.com/login"
        ]
        generate_fresh_scan_data(
            urls=urls_to_scan,
            output_path=Path("results/report_data.json"),
            timeout_ms=15000,
            max_workers=4
        )
        sys.exit(0)

    # ✨ שלב 1: enrich data before rendering
    tests = load_all_scan_results(args.json_path)
    report_data = summarize_tests(tests)

    if args.output.suffix.lower() != ".html":
        logging.error("Output file must have .html extension: %s", args.output.suffix)
        sys.exit(1)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    if not os.access(args.output.parent, os.W_OK):
        logging.error("No write permission for directory: %s", args.output.parent)
        sys.exit(1)

    # Render secure HTML report
    timestamp = datetime.now().isoformat(sep=" ", timespec="seconds")
    nonce = secrets.token_urlsafe(16)
    html_content = render_html(report_data, timestamp, nonce)

    try:
        safe_write(args.output, html_content)
        logging.info("✅ Secure report created at %s", args.output)
    except Exception as e:
        logging.exception("❌ Failed to write report: %s", e)
        sys.exit(1)

    # Optional console summary
    summarize_tests(report_data)

    # Generate summary HTML for scan results
    try:
        # ✨ שלב 2: הוסר fetch נוסף של load_all_scan_results
        summary_data = summarize_tests(tests)
        summary_path = Path(f"reports/{date.today().isoformat()}/summary.html")
        print("🔍 summary_data:", summary_data)
        summary_html = render_summary_html(summary_data["tests"])
        safe_write(summary_path, summary_html)
        print(f"✅ Summary saved to: {summary_path}")
    except Exception as e:
        logging.error("❌ Failed to generate summary report: %s", e)


if __name__ == "__main__":
    print("🚀 Starting full test pipeline...")
    main()
