# LinkShield — Smart URL Threat Scanner

**LinkShield** is a modular, Python-based system designed to scan URLs and detect malicious patterns through multiple security analysis layers. It provides a clean REST API, deterministic risk scoring, and comprehensive threat detection capabilities.

The system combines JavaScript behavior analysis, iframe detection, redirect chain monitoring, visual inspection via OCR, and network anomaly detection to provide accurate security assessments.

---

## Key Features

- **Multi-Signal Detection Engine** — Combines JS behavior, iframe analysis, redirect monitoring, visual/OCR inspection, and network anomaly detection
- **Deterministic Risk Scoring** — Consistent risk scores (0-100), status classification (safe/suspicious/malicious), and detailed reason tracking
- **REST API with FastAPI** — Clean endpoints for scanning, health checks, and interactive API documentation
- **Production-Ready** — Full type coverage, 45/45 tests passing, zero lint warnings, Docker-ready deployment
- **Interactive Reporting** — Generate HTML and PDF reports with visual charts and detailed analysis
- **Modular Architecture** — Clean separation between executors, signals, scanners, and services

---

## Quick Start

### Installation

```bash
git clone https://github.com/yourusername/linkshield.git
cd linkshield
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Run the API Server

```bash
uvicorn app.linkshield_api:app --host 127.0.0.1 --port 8000 --reload
```

Visit `http://127.0.0.1:8000/docs` for interactive API documentation (Swagger UI).

### Example API Request

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Response:**
```json
{
  "url": "https://example.com",
  "status": "safe",
  "risk_score": 0,
  "reasons": [],
  "final_url": "https://example.com",
  "raw": { ... }
}
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Redirects to API documentation |
| `/scan` | POST | Scan a URL and return security analysis |
| `/health` | GET | Health check endpoint |
| `/docs` | GET | Interactive API documentation (Swagger UI) |

---

## Architecture Overview

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ▼
┌─────────────────────┐
│   FastAPI Server    │
│  (linkshield_api)   │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│   ScanService       │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐      ┌──────────────────────┐
│   LinkScanner       │ ───► │  Signal Engines:     │
└──────┬──────────────┘      │  - JS Behavior       │
       │                     │  - Iframe Detection  │
       ▼                     │  - Visual/OCR        │
┌─────────────────────┐      │  - Network Anomaly   │
│   Executor          │      └──────────────────────┘
│  (Browser/Fake)     │
└─────────────────────┘
       │
       ▼
┌─────────────────────┐
│   Raw Data + Risk   │
│   Assessment        │
└─────────────────────┘
```

**Components:**
- **Executor** — Fetches URL content (BrowserExecutor for live, FakeExecutor for testing)
- **Signal Engines** — Analyze specific threat patterns
- **LinkScanner** — Orchestrates execution and risk evaluation
- **ScanService** — Service layer for validation and error handling
- **FastAPI Server** — REST API exposure

---

## Running Tests

The project includes a comprehensive test suite with 45 tests covering all major components.

```bash
# Run all tests
pytest -q

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_scanner/test_link_scanner.py

# Run with coverage
pytest --cov=app --cov-report=html
```

**Current Status:** 45/45 tests passing, 0 lint errors

---

## Development Setup

### Prerequisites

- Python 3.12+
- Virtual environment
- (Optional) Playwright for browser-based scanning

### Environment Configuration

Create a `.env` file in the project root:

```env
# Execution settings
TIMEOUT_MS=10000
DEMO_MODE=true

# Email reporting (optional)
EMAIL_USER=your_email@example.com
EMAIL_PASS=your_app_password

# Browser settings (optional)
HEADLESS=true
```

### Type Checking

```bash
# Using basedpyright
basedpyright app/ tests/

# Expected output: 0 errors, 0 warnings, 0 notes
```

### Code Quality

```bash
# Linting
basedpyright .

# Testing
pytest -q

# Both should pass with zero errors
```

---

## Project Structure

```
linkshield_project/
├── app/
│   ├── infra/
│   │   ├── browser_executor.py      # Playwright-based executor
│   │   └── security/                # Security utilities
│   ├── scanner/
│   │   ├── link_scanner.py          # Main scanning orchestrator
│   │   ├── fake_executor.py         # Test executor
│   │   ├── exceptions.py            # Custom exceptions
│   │   └── signals/                 # Detection engines
│   │       ├── js_behavior_signal.py
│   │       ├── iframe_signal.py
│   │       ├── visual_signal.py
│   │       └── network_anomaly_signal.py
│   ├── services/
│   │   └── scan_service.py          # Service layer
│   ├── reports/                     # Report generation
│   └── linkshield_api.py            # FastAPI application
├── tests/
│   ├── test_scanner/
│   ├── test_services/
│   ├── test_signals/
│   └── conftest.py
├── scripts/
│   └── reporting/                   # Report utilities
├── requirements.txt
├── pyproject.toml
├── pytest.ini
└── README.md
```

---

## Risk Scoring System

LinkShield uses a deterministic scoring system (0-100) with three status levels:

- **Safe (0-49):** No significant threats detected
- **Suspicious (50-94):** Potential threats requiring review
- **Malicious (95-100):** Clear malicious indicators

**Signal Weights:**
- Console messages: 10
- Multiple redirects: 30
- URL keywords: 30
- OCR/Visual: 30
- Iframe detection: 60
- JS behavior: 25

---

## Contributing

Contributions are welcome. Please ensure:
1. All tests pass (`pytest -q`)
2. No lint errors (`basedpyright .`)
3. Type hints are complete
4. Code follows existing patterns

---

## Author

**Dor Ben Arye (Ramp404)**  
Information Systems Engineering Student  
Passionate about cybersecurity, cloud computing, and system design

---

## License

MIT License © 2025 Dor Ben Arye

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
