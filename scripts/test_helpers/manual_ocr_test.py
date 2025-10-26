from app.scanner.link_scanner import LinkScanner
from app.scanner.fake_executor import FakeExecutor

# Create executor and pass it to scanner
executor = FakeExecutor(timeout_ms=10000)
scanner = LinkScanner(executor)

url = "https://accounts.google.com"
result = scanner.scan(url)

# הצגת הטקסט ש־OCR קרא מהצילום מסך
ocr_text = result["raw"].get("ocr_text", "")
print("\n🧠 OCR TEXT EXTRACTED:\n")
print(ocr_text if ocr_text.strip() else "[No text extracted from screenshot]")
