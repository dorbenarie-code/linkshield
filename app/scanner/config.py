# app/scanner/config.py
from dataclasses import dataclass, field
from typing import Mapping, Optional, Any

# תיעודי בלבד: המפתחות הנפוצים אצלך; לא מחייב
WeightMap = Mapping[str, int]

@dataclass(frozen=True)
class ScannerConfig:
    """Immutable view של קונפיג רלוונטי לסריקה."""
    redirect_threshold: int = 2
    network_timeout_ms: Optional[int] = None
    # שומרים מקום למשקלים בעתיד, אבל לא משתמשים בהם בשלב הזה כדי לא לשנות התנהגות
    signal_weights: WeightMap = field(default_factory=dict)

def from_scanner(scanner: Any) -> ScannerConfig:
    """שולף את הערכים הקיימים מה-Scanner כדי לא לשנות התנהגות."""
    return ScannerConfig(
        redirect_threshold=getattr(scanner, "SUSPICIOUS_REDIRECT_COUNT", 2),
        network_timeout_ms=getattr(scanner, "NETWORK_TIMEOUT_MS", None),
        signal_weights=getattr(scanner, "SIGNAL_WEIGHTS", {}),
    )

