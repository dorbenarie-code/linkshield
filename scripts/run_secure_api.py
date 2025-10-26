# scripts/run_secure_api.py

import sys
from pathlib import Path

# ✅ Add project root to sys.path so imports from app/ work
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvicorn
from app.linkshield_api import app
from app.infra.security.ssl_context_loader import create_strict_ssl_context


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8443,
        ssl_keyfile="certs/key.pem",
        ssl_certfile="certs/cert.pem"
    )
