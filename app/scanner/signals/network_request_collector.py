# app/scanner/signals/network_request_collector.py

from typing import List, Dict

class NetworkRequestCollector:
    """
    Collects all network requests made by the page.
    """

    def __init__(self):
        self.requests: List[Dict] = []

    def attach(self, page):
        """
        Attach listener to a Playwright page object.
        """
        page.on("request", self._handle_request)

    def _handle_request(self, request):
        self.requests.append({
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
            "post_data": request.post_data or None,
        })

    def get_requests(self) -> List[Dict]:
        return self.requests
