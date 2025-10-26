"""
Type definitions and protocols for the scanner module.
Defines contracts for executors and scan results.
"""
from __future__ import annotations
from typing import Protocol, Dict, Any, List
from typing_extensions import TypedDict


class ScanResultDict(TypedDict, total=False):
    """Type definition for scan result dictionary."""
    url: str
    status: str         # "safe" | "suspicious" | "malicious"
    risk_score: int     # 0..100
    reasons: List[str]
    raw: Dict[str, Any]
    final_url: str


class Executor(Protocol):
    """
    Protocol defining the interface for browser/test executors.
    Any executor (real or fake) should implement these methods.
    """
    
    def run_url(self, url: str) -> Dict[str, Any]:
        """
        Execute URL fetch and return raw data.
        
        Args:
            url: The URL to fetch
            
        Returns:
            Dictionary containing raw execution data (network logs, screenshots, etc.)
        """
        ...
    
    def __enter__(self) -> Executor:
        """Context manager entry."""
        ...
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        ...

