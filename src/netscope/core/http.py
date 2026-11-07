from __future__ import annotations
import ssl
import urllib.error
import urllib.request
from time import monotonic
from .models import Check


def check_https(url: str = "https://example.com/", timeout: float = 5) -> Check:
    started = monotonic()
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "NetScope/0.1"})
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            return Check(True, f"HTTPS responds: HTTP {response.status}", round((monotonic()-started)*1000,1))
    except urllib.error.HTTPError as exc:
        # An HTTP error status still proves HTTPS/TLS/HTTP server reachability.
        return Check(True, f"HTTPS reached server: HTTP {exc.code}", round((monotonic()-started)*1000,1))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return Check(False, f"HTTPS request failed: {exc}", round((monotonic()-started)*1000,1))
