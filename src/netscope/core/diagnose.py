"""Orchestrate read-only network checks and make cautious observations."""
from __future__ import annotations
from dataclasses import asdict
from datetime import datetime, timezone
import platform
from netscope import __version__
from .adapters import list_adapters
from .dns import check_dns
from .http import check_https, check_https_windows, is_certificate_error
from .ping import ping
from .routes import get_default_routes, trace_route


def explain(*, ping_received: int, dns_ok: bool, https_ok: bool,
            tls_error: bool = False, windows_https_ok: bool | None = None) -> list[str]:
    findings = []
    if dns_ok and https_ok:
        findings.append("DNS and HTTPS to the test site work. This does not guarantee all sites/games work.")
    if not dns_ok:
        findings.append("DNS lookup failed. Check DNS configuration or filtering; this test alone does not identify the cause.")
    if tls_error and windows_https_ok:
        findings.append(
            "Windows Schannel accepts HTTPS while Python/OpenSSL cannot verify its certificate chain. "
            "A missing intermediate CA or VPN/proxy interception are possible. Do NOT disable TLS verification."
        )
    elif tls_error:
        findings.append("Python cannot verify the HTTPS certificate chain. Investigate the certificate and proxy/VPN path; do NOT disable TLS verification.")
    elif not https_ok:
        findings.append("HTTPS to the test site failed. Possible causes include access restrictions, proxy/VPN, TLS or server issues.")
    if ping_received == 0 and https_ok:
        findings.append("HTTPS works but ping did not reply: ICMP may be filtered; do not conclude internet is down.")
    elif ping_received == 0:
        findings.append("The ping target did not respond. ICMP filtering and routing problems are both possible.")
    return findings or ["No clear conclusion; compare results with another connection."]


def diagnose(target: str, domain: str, https_url: str, do_trace: bool = False) -> dict:
    ping_result = ping(target)
    dns_result, addresses = check_dns(domain)
    http_result = check_https(https_url)
    tls_error = is_certificate_error(http_result)
    windows_http = check_https_windows(https_url) if tls_error else None
    default_routes, route_note = get_default_routes()
    adapters = list_adapters()
    report = {
        "app_version": __version__,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "system": platform.platform(),
        "ping": asdict(ping_result) | {"loss_percent": ping_result.loss_percent},
        "dns": asdict(dns_result) | {"domain": domain, "ipv4": addresses},
        "https": asdict(http_result) | {"url": https_url, "certificate_error": tls_error},
        "https_windows": asdict(windows_http) if windows_http is not None else None,
        "default_routes": default_routes,
        "route_note": route_note,
        "adapters": [asdict(a) for a in adapters],
        "findings": explain(ping_received=ping_result.received, dns_ok=dns_result.ok,
                            https_ok=http_result.ok, tls_error=tls_error,
                            windows_https_ok=windows_http.ok if windows_http else None),
    }
    if do_trace:
        success, output = trace_route(target)
        report["trace"] = {"target": target, "finished": success, "output": output}
    return report
