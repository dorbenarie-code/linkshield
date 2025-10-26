# scripts/dev_network_scan.py

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.infra.browser_executor import BrowserExecutor

def test_network_signal():
    print("🚀 Running live scan on suspicious URL...")
    test_url = "https://httpbin.org/get?utm_source=tracker&login=true"

    with BrowserExecutor() as executor:
        result = executor.run_url(test_url)
        print("🔎 Network analysis:", result.get("network_analysis"))

if __name__ == "__main__":
    test_network_signal()
