#!/usr/bin/env python3
"""
manual_scan.py: Simple CLI for performing a manual security scan on a URL.
Maintains clear separation of concerns, handles edge cases, and includes English comments.
"""

import sys
import logging
import argparse

from services.scan_service import ScanService

# Configure root logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def parse_args():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Perform a manual security scan on a URL and print human-readable alerts."
    )
    parser.add_argument(
        "url",
        help="The HTTP or HTTPS URL to scan."
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10000,
        help="Navigation timeout in milliseconds (default: 10000)."
    )
    return parser.parse_args()


def format_alerts(js_alerts: dict) -> None:
    """
    Print JavaScript behavior alerts in a clean format.
    """
    if not js_alerts.get("suspicious_js_found", False):
        print("  ✅ No suspicious JS patterns found.")
        return

    for alert in js_alerts.get("alerts", []):
        print(f"  ⚠️  {alert}")


def print_results(result: dict) -> None:
    """
    Print the full scan result: URL, status, risk score, reasons, and JS alerts.
    """
    final_url = result.get("final_url") or result.get("url", "N/A")
    status = result.get("status", "unknown").upper()
    score = result.get("risk_score", 0)

    print(f"\n🧪 Scanned URL : {final_url}")
    print(f"🔐 Status      : {status}")
    print(f"💯 Risk Score : {score}")

    # Print high-level reasons
    reasons = result.get("reasons", [])
    print("\n📋 Reasons:")
    if reasons:
        for reason in reasons:
            print(f"  - {reason}")
    else:
        print("  ✅ No high-level issues detected.")

    # Print JS-specific alerts
    print("\n🧠 JS Behavior Alerts:")
    js_analysis = result.get("raw", {}).get("js_analysis", {})
    format_alerts(js_analysis)


def main():
    """
    Entry point: parse arguments, run scan, and print results.
    """
    args = parse_args()

    service = ScanService(timeout=args.timeout)

    try:
        logging.info(f"Starting scan for {args.url!r} with timeout={args.timeout}ms")
        result = service.run(args.url)
        print_results(result)
    except KeyboardInterrupt:
        logging.warning("Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logging.exception("Scan failed due to unexpected error.")
        print(f"\n❌ Scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()