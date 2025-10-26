from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, HttpUrl, Field
from typing import List, Dict, Any, Optional
from app.services.scan_service import ScanService
from app.scanner.exceptions import ScanError
import ipaddress
from urllib.parse import urlparse
import logging

# --- Pydantic models ---
class ScanRequest(BaseModel):
    url: HttpUrl = Field(..., example="https://example.com")

class ScanResponse(BaseModel):
    url: str
    final_url: Optional[str] = None
    status: str
    risk_score: int
    reasons: List[str]
    raw: Dict[str, Any]

# --- FastAPI app ---
app = FastAPI(title="LinkShield API", description="API for scanning URLs for security threats")

def get_scan_service():
    return ScanService()

def is_private_or_local(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme == "file":
        return True
    if parsed.hostname in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback:
            return True
    except Exception:
        pass
    return False

def validate_url(self, url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: '{url}'")
    if is_private_or_local(url):
        logger.warning(f"Blocked scan for private/local address: {url}")
        raise ValueError("Scanning local/private addresses is not allowed")
    return url

@app.post(
    "/scan",
    response_model=ScanResponse,
    summary="Scan URL for security threats",
    description="Analyzes the provided URL for potential security risks and vulnerabilities"
)
def scan_url(request: ScanRequest, scan_service: ScanService = Depends(get_scan_service)) -> ScanResponse:
    """
    Scan a URL for security threats and return a structured result.
    """
    try:
        logger.info(f"Starting scan for {request.url}")
        result = scan_service.run(str(request.url))
        logger.info(f"Scan for {result.url} returned score {result.risk_score}")
        return ScanResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except ScanError as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unhandled error: {e}")