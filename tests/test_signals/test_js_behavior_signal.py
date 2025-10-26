# tests/test_js_behavior_signal.py

import unittest
from app.scanner.signals.js_behavior_signal import JSBehaviorSignal, detect_js_behaviors

class TestJSBehaviorSignal(unittest.TestCase):
    """Unit tests for JavaScript behavior signal detection."""

    def setUp(self):
        # use default patterns
        self.detector = JSBehaviorSignal()

    def run_detection(self, raw):
        """Helper to call both class and facade and compare results."""
        direct = self.detector.detect(raw)
        facade = detect_js_behaviors(raw)
        self.assertEqual(direct, facade)
        return direct

    def test_no_data(self):
        """Empty raw_data should yield no alerts and zero counts."""
        result = self.run_detection({})
        self.assertFalse(result["suspicious_js_found"])
        self.assertEqual(result["alerts"], [])
        self.assertEqual(result["match_count"], 0)
        self.assertEqual(result["matched_patterns"], [])
        self.assertEqual(result["console_entries"], [])
        self.assertEqual(result["html_entries"], [])
        self.assertEqual(result["js_raw_entries"], [])

    def test_safe_console_and_html(self):
        """Safe console & HTML produce no alerts."""
        raw = {
            "console_messages": ["All good", ""],
            "html": "<div>hello world</div>"
        }
        result = self.run_detection(raw)
        self.assertFalse(result["suspicious_js_found"])
        self.assertEqual(result["match_count"], 0)
        self.assertEqual(result["matched_patterns"], [])

    def test_eval_and_new_function_console(self):
        """Detect eval and new Function from console, count and patterns correct."""
        logs = ["Let's eval('x')", "new FUNCTION('a','b','return')"]
        raw = {"console_messages": logs}
        result = self.run_detection(raw)
        self.assertTrue(result["suspicious_js_found"])
        self.assertEqual(result["match_count"], 2)

        # check eval pattern exactly escaped
        self.assertTrue(any(p == "eval\\(" for p in result["matched_patterns"]))
        # check new Function case-insensitively
        self.assertTrue(any("new function" in p.lower() for p in result["matched_patterns"]))

    def test_fingerprint_and_atob_mixed(self):
        """Detect fingerprint in html, atob in js_raw, mixed list and string in js_raw."""
        raw = {
            "console_messages": [],
            "html": "<script>var fp = window.fingerprint();</script>",
            "js_raw": ["atob('YWJj');", "eval('1');"]
        }
        result = self.run_detection(raw)
        self.assertTrue(result["suspicious_js_found"])
        # fingerprint pattern without parentheses
        cleaned = [p.replace("\\", "") for p in result["matched_patterns"]]
        self.assertIn("fingerprint", cleaned)
        self.assertIn("atob\\(", result["matched_patterns"])
        self.assertIn("eval\\(", result["matched_patterns"])
        self.assertEqual(result["match_count"], 3)

    def test_mixed_console_and_js_raw_and_list(self):
        """console_messages as string and js_raw as mixed list+string entries."""
        raw = {
            "console_messages": "Crypto.Subtle.importKey()",
            "html": None,
            "js_raw": ["btoa('data')", "new Function('a')"]  # corrected typo from "BToB"
        }
        result = self.run_detection(raw)
        self.assertTrue(result["suspicious_js_found"])
        self.assertCountEqual(
            result["matched_patterns"],
            ["crypto\\.subtle", "btoa\\(", "new Function\\("]
        )
        self.assertEqual(result["match_count"], 3)

    def test_no_duplicate_alerts_for_same_entry(self):
        """Ensure only one alert per entry, even if multiple patterns match."""
        text = "eval('code'); setTimeout(fn,1000);"
        raw = {"console_messages": [text]}
        result = self.run_detection(raw)
        self.assertEqual(result["match_count"], 1)
        self.assertEqual(len(result["matched_patterns"]), 1)

    def test_non_list_console_messages(self):
        """console_messages as unexpected type should be treated as empty."""
        raw = {"console_messages": 123, "html": "document.write('x');"}
        result = self.run_detection(raw)
        self.assertTrue(result["suspicious_js_found"])
        self.assertEqual(result["match_count"], 1)
        self.assertIn("document\\.write\\(", result["matched_patterns"])

    def test_scale_with_many_entries(self):
        """Scale test: large number of console logs with a single suspicious entry."""
        logs = [f"log message {i}" for i in range(100)]
        logs.append("eval('x')")
        raw = {"console_messages": logs}
        result = self.run_detection(raw)
        self.assertTrue(result["suspicious_js_found"])
        self.assertEqual(result["match_count"], 1)
        self.assertEqual(result["matched_patterns"], ["eval\\("])

    def test_matched_patterns_are_escaped(self):
        """Verify matched_patterns contains escaped patterns, not raw."""
        raw = {"console_messages": ["btoa('abc')"]}
        result = self.run_detection(raw)
        # raw pattern is 'btoa(', escaped is 'btoa\('
        self.assertIn("btoa\\(", result["matched_patterns"])
        self.assertNotIn("btoa(", result["matched_patterns"])

if __name__ == "__main__":
    unittest.main()
