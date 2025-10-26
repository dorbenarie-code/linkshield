# app/reports/renderers/summary_stats.py

import time
from typing import Any, Dict, List

Tests = List[Dict[str, Any]]
PassedStatuses = {"clean", "ok", "pass"}


def is_passed(status: str) -> bool:
    """
    Return True if the status indicates a passing test.
    """
    return status.strip().lower() in PassedStatuses


def compute_summary(tests: Tests) -> Dict[str, Any]:
    """
    Compute summary statistics for test results.

    Args:
        tests (Tests): A list of test result dictionaries.

    Returns:
        Dict[str, Any]: A dictionary with keys:
            - total: Total number of tests
            - passed: Number of successful tests
            - failed: Number of failed tests
            - duration: Computation time in seconds (rounded)
    """
    start_time = time.perf_counter()

    total = len(tests)
    passed = sum(1 for t in tests if is_passed(t.get("status", "")))
    failed = total - passed

    duration = round(time.perf_counter() - start_time, 4)

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "duration": duration
    }
