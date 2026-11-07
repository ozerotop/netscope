"""Independent HTTPS checks: Python/OpenSSL and, when needed, Windows Schannel."""
from __future__ import annotations
import re
import ssl
import urllib.error
import urllib.request
from time import monotonic
from .models import Check
from .windows import run_windows


def check_https(url: str = "https://www.python.org/", timeout: float = 5) -> Check:
    started = monotonic()
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "NetScope/0.2"})
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            return Check(True, f"HTTPS responds: HTTP {response.status}", round((monotonic()-started)*1000,1))
    except urllib.error.HTTPError as exc:
        # An HTTP status error still confirms successful TLS and server response.
        return Check(True, f"HTTPS reached server: HTTP {exc.code}", round((monotonic()-started)*1000,1))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return Check(False, f"HTTPS request failed: {exc}", round((monotonic()-started)*1000,1))


def is_certificate_error(check: Check) -> bool:
    return "certificate_verify_failed" in check.detail.casefold() or "certificate verify failed" in check.detail.casefold()


def check_https_windows(url: str, timeout: int = 8) -> Check:
    """Check Schannel via bundled Windows curl, without --insecure or -k.

    This is a comparison only: an OK here does not override Python TLS errors.
    """
    started = monotonic()
    try:
        code, output = run_windows(
            ["curl.exe", "--head", "--silent", "--show-error", "--max-time", str(timeout),
             "--output", "NUL", "--write-out", "%{http_code}", url],
            timeout=timeout + 3,
        )
        match = re.search(r"(\d{3})\s*$", output)
        status = match.group(1) if match else "unknown"
        if code == 0:
            return Check(True, f"Windows Schannel accepted HTTPS (HTTP {status})", round((monotonic()-started)*1000,1))
        return Check(False, f"Windows curl failed (exit {code}): {output[:300]}", round((monotonic()-started)*1000,1))
    except (OSError, RuntimeError, TimeoutError) as exc:
        return Check(False, f"Windows curl unavailable: {exc}", round((monotonic()-started)*1000,1))
