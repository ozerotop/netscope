"""Offline rule engine: observations vs uncertain causes."""
from copy import deepcopy
import pytest
from netscope.core.insights import analyze_report, validate_investigation


def sample():
    return {
        "app_version": "0.4.0", "created_utc": "2026-11-07T22:16:28+00:00",
        "dns": {"domain": "www.python.org", "answers_differ": False, "results": [
            {"server": "Windows (системный резолвер)", "transport": "system API", "ok": True, "ipv4": ["151.101.0.223"]},
            {"server": "1.1.1.1", "transport": "UDP/53 (unencrypted)", "ok": True, "ipv4": ["151.101.0.223"]},
        ]},
        "route": {"destination": "1.1.1.1", "ok": True, "error": "", "ambiguous": False,
                  "best": {"network": "0.0.0.0/0", "gateway": "On-link", "interface": "172.19.0.1", "metric": 0, "prefix_length": 0}},
        "tcp": {"host": "www.python.org", "port": 443, "ok": True},
        "adapters": [
            {"name": "happ-xray", "is_up": True, "vpn_candidate": True, "ipv4": ["172.19.0.1"]},
            {"name": "Radmin VPN", "is_up": True, "vpn_candidate": True, "ipv4": ["26.0.0.1"]},
        ],
    }


def codes(report):
    return {item["code"] for item in analyze_report(report)["items"]}


def test_realistic_report_rules():
    result = analyze_report(sample())
    assert {"dns_ok", "route_selected", "vpn_default_route", "multiple_vpn", "tcp_ok"} <= codes(sample())
    assert result["summary"]["warning"] == 0


def test_no_claim_vpn_conflict():
    assert all("конфликт" not in item["title"].lower() for item in analyze_report(sample())["items"])


def test_dns_all_failure():
    r = sample()
    for row in r["dns"]["results"]:
        row["ok"] = False
        row["ipv4"] = []
    assert "dns_all_failed" in codes(r)


def test_dns_empty_results():
    r = sample()
    r["dns"]["results"] = []
    assert "dns_all_failed" in codes(r)


def test_system_failure_direct_success():
    r = sample()
    r["dns"]["results"][0]["ok"] = False
    assert "system_dns_failed" in codes(r)


def test_system_success_direct_failure():
    r = sample()
    r["dns"]["results"][1]["ok"] = False
    assert "direct_dns_failed" in codes(r)


def test_dns_different_not_proof_spoofing():
    r = sample()
    r["dns"]["answers_differ"] = True
    row = next(x for x in analyze_report(r)["items"] if x["code"] == "dns_answers_differ")
    assert "CDN" in row["explanation"]


def test_tcp_failure():
    r = sample()
    r["tcp"]["ok"] = False
    assert "tcp_failed" in codes(r)


def test_missing_route():
    r = sample()
    r["route"]["best"] = None
    assert "route_missing" in codes(r)
    assert "vpn_default_route" not in codes(r)


def test_route_ambiguous():
    r = sample()
    r["route"]["ambiguous"] = True
    assert "route_ambiguous" in codes(r)


def test_onlink_without_matching_vpn():
    r = sample()
    r["route"]["best"]["interface"] = "192.168.1.2"
    assert "vpn_default_route" not in codes(r)


def test_no_vpn_candidate():
    r = sample()
    r["adapters"] = []
    assert "multiple_vpn" not in codes(r)

@pytest.mark.parametrize("missing", ["dns", "route", "tcp", "adapters"])
def test_report_requires_advanced_structure(missing):
    r = sample()
    del r[missing]
    with pytest.raises(ValueError):
        validate_investigation(r)


def test_basic_report_rejected():
    with pytest.raises(ValueError):
        analyze_report({"ping": {"received": 4}, "https": {"ok": True}})


def test_invalid_dns_row_rejected():
    r = sample()
    r["dns"]["results"] = [{"ok": "yes", "ipv4": []}]
    with pytest.raises(ValueError):
        analyze_report(r)


def test_pure_no_mutation():
    r = sample()
    original = deepcopy(r)
    analyze_report(r)
    assert r == original
