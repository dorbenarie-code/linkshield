from scanner.link_scanner import LinkScanner
import pprint

scanner = LinkScanner(retries=1, executor_config={"timeout": 5000})

try:
    result = scanner.scan("https://example.com")
    pprint.pprint(result)
except Exception as e:
    print("❌ Direct scan failed:")
    import traceback
    traceback.print_exc()
