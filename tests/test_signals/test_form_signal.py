# form_signal_with_tests.py

from typing import Dict, Any, List
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import unittest

# ——————————————————————————————————————————————
# Logic layer: form_signal
# ——————————————————————————————————————————————

def detect_form_issues(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze HTML forms and flag suspicious patterns:
      1. Submissions over plain HTTP (non-SSL)
      2. Submissions to an external domain
      3. Presence of password input fields

    Args:
        raw: dict with keys:
          - html: the page HTML as a string
          - final_url: the page URL where forms originate

    Returns:
        Dict with:
          - suspicious_forms_found: bool
          - reasons: List of human-readable strings explaining each issue
    """
    html = raw.get("html") or ""
    final_url = raw.get("final_url") or ""
    if not html or not final_url:
        return {"suspicious_forms_found": False, "reasons": []}

    # Determine the domain of the originating page
    try:
        final_domain = urlparse(final_url).netloc.lower()
    except Exception:
        final_domain = ""

    soup = BeautifulSoup(html, "lxml")
    forms = soup.find_all("form")

    raw_reasons: List[str] = []
    for form in forms:
        action_attr = (form.get("action") or "").strip()
        if not action_attr:
            # No action = submits back to same page → treat as safe
            continue

        # Resolve relative URLs against the page URL
        action_url = urljoin(final_url, action_attr)
        parsed = urlparse(action_url)
        scheme = parsed.scheme.lower()
        domain = parsed.netloc.lower()

        # 1. Non-SSL submission
        if scheme == "http":
            raw_reasons.append("Form submits via non-SSL (http) endpoint")

        # 2. External-domain submission
        if domain and final_domain and domain != final_domain:
            raw_reasons.append(f"Form submits to external domain: {domain}")

        # 3. Password input detected
        if form.find("input", {"type": "password"}):
            raw_reasons.append("Form contains a password input field")

    # Deduplicate while preserving order
    seen = set()
    reasons: List[str] = []
    for reason in raw_reasons:
        if reason not in seen:
            seen.add(reason)
            reasons.append(reason)

    return {
        "suspicious_forms_found": bool(reasons),
        "reasons": reasons
    }


# ——————————————————————————————————————————————
# Test layer: TestFormSignal
# ——————————————————————————————————————————————

class TestFormSignal(unittest.TestCase):
    """Unit tests for the form issue detection logic."""

    def run_detection(self, html: str, final_url: str) -> Dict[str, Any]:
        """
        Helper to run detect_form_issues with given HTML and final URL.
        """
        raw = {"html": html, "final_url": final_url}
        return detect_form_issues(raw)

    def test_safe_form(self):
        """HTTPS form to same domain should be considered safe."""
        html = '''
        <html><body>
        <form action="https://example.com/submit">
            <input type="text" name="email"/>
        </form>
        </body></html>
        '''
        result = self.run_detection(html, "https://example.com")
        self.assertFalse(result["suspicious_forms_found"])
        self.assertEqual(result["reasons"], [])

    def test_password_input_detected(self):
        """Presence of a password field must be flagged as suspicious."""
        html = '''
        <html><body>
        <form action="https://example.com/login">
            <input type="password" name="pwd"/>
        </form>
        </body></html>
        '''
        result = self.run_detection(html, "https://example.com")
        self.assertTrue(result["suspicious_forms_found"])
        self.assertTrue(
            any("password" in reason.lower() for reason in result["reasons"]),
            msg="Expected at least one reason containing 'password'"
        )

    def test_non_ssl_submission(self):
        """Forms submitting over HTTP (non-SSL) should be flagged."""
        html = '''
        <html><body>
        <form action="http://evil.com/submit">
            <input type="text" name="email"/>
        </form>
        </body></html>
        '''
        result = self.run_detection(html, "https://example.com")
        self.assertTrue(result["suspicious_forms_found"])
        self.assertTrue(
            any("non-ssl" in reason.lower() for reason in result["reasons"]),
            msg="Expected at least one reason containing 'non-ssl'"
        )

    def test_external_domain_submission(self):
        """Forms posting to a different domain must be flagged."""
        html = '''
        <html><body>
        <form action="https://phishing.com/submit">
            <input type="text" name="email"/>
        </form>
        </body></html>
        '''
        result = self.run_detection(html, "https://example.com")
        self.assertTrue(result["suspicious_forms_found"])
        self.assertTrue(
            any("external domain" in reason.lower() for reason in result["reasons"]),
            msg="Expected at least one reason containing 'external domain'"
        )

    def test_no_forms_present(self):
        """Pages without any form elements should pass as safe."""
        html = '<html><body><p>No forms here!</p></body></html>'
        result = self.run_detection(html, "https://example.com")
        self.assertFalse(result["suspicious_forms_found"])
        self.assertEqual(result["reasons"], [])

    def test_multiple_forms_mixed(self):
        """Only problematic forms should trigger flags in mixed pages."""
        html = '''
        <html><body>
        <!-- Safe form -->
        <form action="https://example.com/submit">
            <input type="text" name="user"/>
        </form>
        <!-- Suspicious form -->
        <form action="http://malicious.com/send">
            <input type="text" name="data"/>
        </form>
        </body></html>
        '''
        result = self.run_detection(html, "https://example.com")
        self.assertTrue(result["suspicious_forms_found"])
        self.assertTrue(
            any("non-ssl" in reason.lower() for reason in result["reasons"]),
            msg="Expected non-SSL reason in mixed forms"
        )
        self.assertTrue(
            any("external domain" in reason.lower() for reason in result["reasons"]),
            msg="Expected external domain reason in mixed forms"
        )

if __name__ == "__main__":
    unittest.main()
