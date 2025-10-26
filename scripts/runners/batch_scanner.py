#!/usr/bin/env python3
"""
Batch scanner script: read URLs, scan each, generate HTML/PDF reports and a central summary.
"""

import sys
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

from app.infra.browser_executor import BrowserExecutor
from app.scanner.link_scanner import LinkScanner
from scripts.custom_report_generator import generate_html_report, export_to_pdf
from app.reports.utils.report_utils import safe_write

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def read_urls(file_path: Path) -> List[str]:
    if not file_path.is_file():
        logging.error(f"Input file not found: {file_path}")
        raise FileNotFoundError(f"Input file not found: {file_path}")

    urls = []
    for line in file_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith(("http://", "https://")):
            logging.warning(f"Skipping invalid URL: {line}")
            continue
        urls.append(line)

    return urls


def create_report_folder(base_dir: Path) -> Path:
    date_str = datetime.now().strftime("%Y-%m-%d")
    folder = base_dir / date_str
    folder.mkdir(parents=True, exist_ok=True)
    logging.info(f"Reports will be saved to: {folder}")
    return folder


def scan_urls(urls: List[str], output_dir: Path, scanner: LinkScanner) -> List[Dict[str, Any]]:
    summary: List[Dict[str, Any]] = []

    for idx, url in enumerate(urls, start=1):
        logging.info(f"Scanning ({idx}/{len(urls)}): {url}")
        try:
            result = scanner.scan(url)
        except Exception as e:
            logging.error(f"Error scanning {url}: {e}")
            summary.append({
                "url": url,
                "status": "error",
                "score": 0,
                "html": "",
                "pdf": ""
            })
            continue

        timestamp = datetime.now().strftime("%H%M%S")
        unique_name = f"scan_{timestamp}_{idx}"
        html_file = f"{unique_name}.html"
        pdf_file = f"{unique_name}.pdf"
        html_path = output_dir / html_file
        pdf_path = output_dir / pdf_file

        try:
            html_content = render_scan_result_html(result)
            safe_write(html_path, html_content)
        except Exception as e:
            logging.error(f"Failed HTML for {url}: {e}")

        try:
            export_to_pdf(html_path, pdf_path)
        except Exception as e:
            logging.error(f"Failed PDF for {url}: {e}")

        summary.append({
            "url": result.get("url", url),
            "status": result.get("status", "unknown"),
            "score": result.get("risk_score", 0),
            "html": html_file,
            "pdf": pdf_file
        })

    return summary


def generate_summary(summary_data: List[Dict[str, Any]], output_dir: Path):
    rows = ""
    for entry in summary_data:
        rows += (
            "<tr>"
            f"<td>{entry['url']}</td>"
            f"<td>{entry['status']}</td>"
            f"<td>{entry['score']}</td>"
            f"<td><a href=\"{entry['html']}\">HTML</a></td>"
            f"<td><a href=\"{entry['pdf']}\">PDF</a></td>"
            "</tr>\n"
        )

    summary_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Batch Scan Summary</title>
<style>
  table {{border-collapse: collapse; width: 100%;}}
  th, td {{border: 1px solid #ccc; padding: 8px; text-align: left;}}
  th {{background: #f4f4f4;}}
</style>
</head>
<body>
<h2>Scan Summary - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</h2>
<table>
  <tr><th>URL</th><th>Status</th><th>Score</th><th>HTML</th><th>PDF</th></tr>
  {rows}
</table>
</body>
</html>
"""
    summary_path = output_dir / "summary.html"
    safe_write(summary_path, summary_html)
    logging.info(f"Summary saved to: {summary_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch URL scanner")
    parser.add_argument("input_file", type=Path, help="Text file containing one URL per line")
    parser.add_argument("-o", "--output", type=Path, default=Path("reports"),
                        help="Base directory for all reports (default: reports)")
    return parser.parse_args()

def render_scan_result_html(data: dict) -> str:
    """
    Render a simple but elegant HTML report for a single scanned URL.
    """
    url = data.get("url", "-")
    status = data.get("status", "unknown")
    score = data.get("risk_score", 0)
    reasons = data.get("reasons", [])
    screenshot = data.get("screenshot")

    status_colors = {
        "clean": "#2ecc71",
        "suspicious": "#f39c12",
        "malicious": "#e74c3c",
        "unknown": "#7f8c8d"
    }
    color = status_colors.get(status, "#7f8c8d")

    reasons_html = "<ul>" + "".join(f"<li>{r}</li>" for r in reasons) + "</ul>" if reasons else "<p>–</p>"

    screenshot_html = (
        f"<p><img src='{screenshot}' alt='Screenshot' style='max-width:100%; border:1px solid #ccc;'></p>"
        if screenshot else "<p><em>No screenshot available</em></p>"
    )

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Scan Report - {url}</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f9f9f9; padding: 2em; }}
            .box {{ background: #fff; padding: 2em; border-radius: 8px; max-width: 800px; margin: auto; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            h1 {{ color: {color}; }}
            ul {{ line-height: 1.6; }}
            .meta {{ margin-top: 1em; font-size: 0.9em; color: #555; }}
        </style>
    </head>
    <body>
        <div class="box">
            <h1>Status: {status.upper()}</h1>
            <p><strong>URL:</strong> {url}</p>
            <p><strong>Risk Score:</strong> {score}</p>
            <p><strong>Reasons:</strong></p>
            {reasons_html}
            <h3>Screenshot:</h3>
            {screenshot_html}
            <div class="meta">
                <p>Generated by LinkShield 🛡️</p>
            </div>
        </div>
    </body>
    </html>
    """


def main():
    args = parse_args()

    try:
        urls = read_urls(args.input_file)
        if not urls:
            logging.warning("No URLs to scan. Exiting.")
            sys.exit(0)

        out_dir = create_report_folder(args.output)

        # ✅ השלב החשוב – הרצה עם executor
        with BrowserExecutor() as executor:
            scanner = LinkScanner(executor)
            summary = scan_urls(urls, out_dir, scanner)

        generate_summary(summary, out_dir)

    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
