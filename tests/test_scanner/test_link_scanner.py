# scanner/test_link_scanner.py
from app.infra.browser_executor import BrowserExecutor
from app.scanner.fake_executor import FakeExecutor



import unittest
from app.scanner.link_scanner import LinkScanner

class TestLinkScanner(unittest.TestCase):
    """Integration and edge‐case tests for the LinkScanner class."""

    def setUp(self):
        """
        Initialize a LinkScanner with minimal retries and a short timeout
        to keep test execution fast.
        """
        self.scanner = LinkScanner(FakeExecutor(timeout_ms=3000))


    def assertScanResult(self, url, expected_status, expected_score):
        """
        Helper to assert common properties of a scan result.
        """
        result = self.scanner.scan(url)
        # The URL in the result should match the input
        self.assertEqual(result['url'], url)
        # Status and score should match expectations
        self.assertEqual(result['status'], expected_status)
        self.assertEqual(result['risk_score'], expected_score)
        # 'reasons' should be a list, 'raw' should be a dict
        self.assertIsInstance(result['reasons'], list)
        self.assertIsInstance(result['raw'], dict)

    def test_safe_url(self):
        """A standard page with no suspicious behavior is classified as safe."""
        self.assertScanResult('https://www.wikipedia.org', 'safe', 10)

    def test_redirect_chain(self):
        """
        A URL that redirects more than once is classified as suspicious
        with at least the base suspicious score.
        """
        self.assertScanResult('https://httpbin.org/redirect/2', 'suspicious', 60)

    def test_ssl_error(self):
        """An expired SSL certificate should be classified as malicious."""
        result = self.scanner.scan('https://expired.badssl.com/')
        self.assertEqual(result['status'], 'malicious')
        self.assertEqual(result['risk_score'], 100)
        # Expect at least one reason mentioning an error
        self.assertTrue(any('Error' in r for r in result['reasons']))

    def test_http_error(self):
        """An HTTP 404 response is classified as malicious."""
        self.assertScanResult('https://httpbin.org/status/404', 'malicious', 100)

    def test_plain_html(self):
        """A simple HTML page without console messages remains safe."""
        self.assertScanResult('https://httpbin.org/html', 'safe', 10)

    def test_suspicious_keyword(self):
        """URLs containing keywords like 'login' are classified as suspicious."""
        self.assertScanResult('https://accounts.google.com/login', 'suspicious', 60)

    def test_invalid_scheme(self):
        """Non‐HTTP/HTTPS schemes immediately produce a malicious result."""
        result = self.scanner.scan('ftp://example.com')
        self.assertEqual(result['status'], 'malicious')
        self.assertEqual(result['risk_score'], 100)
        self.assertTrue(result['reasons'][0].startswith('Error'))

    def test_unresolvable_domain(self):
        """A domain that can't be resolved is classified as malicious."""
        result = self.scanner.scan('https://nonexistent.domain.xyz')
        self.assertEqual(result['status'], 'malicious')
        self.assertEqual(result['risk_score'], 100)
        # The reason should mention a network or resolution error
        self.assertTrue(any('error' in r.lower() for r in result['reasons']))

if __name__ == '__main__':
    unittest.main()
