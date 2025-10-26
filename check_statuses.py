#!/usr/bin/env python3
from pathlib import Path
from app.reports.renderers.summary_loader import load_tests_from_json

def display_statuses(json_path: Path) -> None:
    """
    Load tests from JSON and print unique status values.
    """
    tests = load_tests_from_json(json_path)
    if not tests:
        print(f"❗ No tests loaded from: {json_path}")
        return

    statuses = {t.get("status", "MISSING").strip().lower() for t in tests}
    sorted_statuses = sorted(statuses)

    print("📊 Detected status values:", ", ".join(sorted_statuses))


def main() -> None:
    # Correct JSON file path
    json_path: Path = Path("app/data/report_data.json")
    display_statuses(json_path)


if __name__ == "__main__":
    main()
