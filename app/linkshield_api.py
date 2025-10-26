# app/main.py

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, HttpUrl

from app.scanner.fake_executor import FakeExecutor
from app.scanner.link_scanner import LinkScanner

import traceback


app = FastAPI()

executor = FakeExecutor(timeout_ms=10000)
scanner = LinkScanner(executor)


class ScanRequest(BaseModel):
    url: HttpUrl

@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    """Redirect root to API docs"""
    return RedirectResponse(url="/docs")

@app.get("/health", tags=["meta"])
def health() -> JSONResponse:
    """Health check endpoint"""
    return JSONResponse({"ok": True, "app": "LinkShield API"})

@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    """Silent favicon handler to avoid 404s in logs"""
    return Response(status_code=204)

@app.post("/scan")
def scan_url(request: ScanRequest):
    try:
        result = scanner.scan(str(request.url))

        return result
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Unhandled error: {e}")
