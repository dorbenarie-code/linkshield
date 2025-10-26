# Integration Tests

This directory contains integration tests that may interact with external resources:
- Real network calls
- Browser automation (Playwright)
- External services

## Running Tests

**Run only unit tests (fast, no network):**
```bash
pytest -m "not integration"
```

**Run only integration tests:**
```bash
pytest -m integration
```

**Run all tests:**
```bash
pytest
```

## Note

Integration tests are automatically marked with `@pytest.mark.integration` via `conftest.py`.
Unit tests in `tests/` (outside this directory) should use `FakeExecutor` and mock data.

