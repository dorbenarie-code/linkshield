#!/usr/bin/env python3
import os
import unittest
import HtmlTestRunner

def main():
    # 1. Prepare report directory
    # You can override via HTML_REPORT_DIR env var
    report_dir = os.getenv('HTML_REPORT_DIR', 'reports')
    os.makedirs(report_dir, exist_ok=True)

    # 2. Configure HTMLTestRunner
    runner = HtmlTestRunner.HTMLTestRunner(
        output=report_dir,                         # where to write reports
        report_name='LinkScannerTestReport',       # base name of the report file
        combine_reports=True,                      # single report for all tests
        add_timestamp=True,                        # append timestamp to filename
        verbosity=2,                               # show detailed test output
        report_title='LinkScanner Test Suite',     # title in the HTML page
        descriptions='Validation of LinkScanner logic and edge cases'  # description section
    )

    # 3. Discover all tests matching test_*.py under "tests/" directory
    loader = unittest.TestLoader()
    test_suite = loader.discover(start_dir='tests', pattern='test_*.py')

    # 4. Run tests and generate HTML report
    runner.run(test_suite)

if __name__ == '__main__':
    # Entry point
    main()
