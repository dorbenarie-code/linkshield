# utils/report_stats.py

import time
from typing import List, Dict, Any

def summarize_tests(tests: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute summary statistics for a list of test results.

    Args:
        tests: A list of dicts, each representing a test result with at least:
               - "status": a string, e.g. "pass" or "fail"

    Returns:
        A dict containing:
          - total:    total number of tests
          - passed:   number of tests with status "pass"
          - failed:   number of tests with status "fail"
          - duration: time taken to compute these metrics (in seconds, rounded)
          - tests:    the original list of tests (unmodified)
    """
    # Ensure we have a list to work with
    test_list = tests if isinstance(tests, list) else []

    # Start high-resolution timer
    start_time = time.perf_counter()

    # Normalize statuses (lowercase) and count outcomes
    statuses = [str(item.get("status", "")).strip().lower() for item in test_list]
    passed = statuses.count("pass")
    failed = statuses.count("fail")
    total = len(statuses)

    # Compute elapsed time
    elapsed = time.perf_counter() - start_time
    duration = round(elapsed, 4)

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "duration": duration,
        "tests": test_list
    }
