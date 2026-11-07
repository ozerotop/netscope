from netscope.core.diagnose import explain


def test_blocked_icmp_not_internet_outage():
    findings = explain(ping_received=0, dns_ok=True, https_ok=True)
    assert any("ICMP" in item for item in findings)
    assert any("HTTPS" in item for item in findings)


def test_dns_failure_flagged():
    findings = explain(ping_received=3, dns_ok=False, https_ok=False)
    assert any("DNS lookup failed" in item for item in findings)
