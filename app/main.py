# main.py

from reports.renderers.summary_renderer import render_summary_html, save_summary_report
from app.utils.mail_utils import send_report_email
from app.infra.browser_executor import BrowserExecutor  # use the real BrowserExecutor
from pathlib import Path
import json

def main():
    # Load scan results from JSON file
    with open("results/report_data.json") as f:
        data = json.load(f)

    print("🔍 File contents:", data)

    # Use the correct key "tests" instead of "scan_results"
    results = data["tests"]
    summary = {
        "total": len(results),
        "passed": sum(1 for r in results if r["status"] == "clean"),
        "failed": sum(1 for r in results if r["status"] != "clean"),
        "duration": round(
            sum(r["raw"].get("load_time_ms", 0) for r in results) / 1000, 2
        )
    }

    # Save HTML report
    summary_path = Path("reports/summary.html")
    save_summary_report(results, summary, summary_path)

    # Send report via email
    send_report_email(
        subject="📊 LinkShield - Daily Security Report",
        body="Attached is the latest security scan report from LinkShield.",
        to_email="dormahalal@gmail.com",
        attachment=summary_path
    )

def test_network_signal():
    # Live network scan test
    print("🚀 Running live scan on suspicious URL...")
    test_url = "http://phishing-site.tk/login?token=abc&utm_source=facebook"

    with BrowserExecutor() as executor:
        result = executor.run_url(test_url)
        print("🔎 Network analysis:", result.get("network_analysis"))

if __name__ == "__main__":
    pass  # FastAPI app is run via uvicorn command
