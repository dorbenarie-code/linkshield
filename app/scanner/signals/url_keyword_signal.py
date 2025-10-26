from urllib.parse import urlparse
from typing import List

SUSPICIOUS_KEYWORDS: List[str] = ["phish", "secure", "login"]

def has_suspicious_url_keyword(url: str) -> bool:
    """
    True אם בדומיין יש מילת חשד; זהה להתנהגות הקודמת.
    לא משנה API חיצוני – רק מחלץ את הלוגיקה.
    """
    domain = (urlparse(url).netloc or "").lower()
    return any(k in domain for k in SUSPICIOUS_KEYWORDS)

