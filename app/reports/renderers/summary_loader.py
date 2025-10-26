# app/reports/renderers/summary_loader.py

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def load_tests_from_json(json_path: Path) -> List[Dict[str, Any]]:
    """
    Load test entries from a JSON file.

    Args:
        json_path (Path): Path to the JSON file containing test results.

    Returns:
        List[Dict[str, Any]]: A list of test dictionaries, or empty list on error.
    """
    # Try reading the file (catches file-not-found & permission errors)
    try:
        raw = json_path.read_text(encoding="utf-8")
    except OSError as e:
        logger.error("Cannot read file %s: %s", json_path, e)
        return []

    # Try parsing JSON
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in %s: %s", json_path, e)
        return []

    # Validate that 'tests' exists and is a list
    tests = payload.get("tests")
    if not isinstance(tests, list):
        logger.error("Expected 'tests' list in %s, got %r", json_path, tests)
        return []

    return tests
