from copy import deepcopy
from netscope.core.report_diff import compare_reports
from test_insights import sample


def by_topic(result, topic):
    return [r for r in result["changes"] if r["topic"] == topic]


def test_same_reports():
    a = sample()
    result = compare_reports(a, deepcopy(a))
    assert result["changed_count"] == 0
    assert all(c["status"] == "same" for c in result["changes"])


def test_tcp_failure_to_success():
    a = sample()
    a["tcp"]["ok"] = False
    r = compare_reports(a, sample())
    assert by_topic(r, "TCP")[0]["status"] == "changed"
    assert "нет соединения" in by_topic(r, "TCP")[0]["description"]


def test_tcp_not_comparable_host_changed():
    a, b = sample(), sample()
    b["tcp"]["host"] = "different.example"
    assert by_topic(compare_reports(a,b), "TCP")[0]["status"] == "not_comparable"


def test_tcp_not_comparable_port_changed():
    a, b = sample(), sample()
    b["tcp"]["port"] = 1234
    assert by_topic(compare_reports(a,b), "TCP")[0]["status"] == "not_comparable"


def test_dns_different_domain_not_comparable():
    a, b = sample(), sample()
    b["dns"]["domain"] = "example.org"
    assert by_topic(compare_reports(a,b), "DNS")[0]["status"] == "not_comparable"


def test_dns_response_changed():
    a, b = sample(), sample()
    b["dns"]["results"][1]["ipv4"] = ["10.0.0.1"]
    assert by_topic(compare_reports(a,b), "DNS")[0]["status"] == "changed"


def test_dns_status_changed():
    a, b = sample(), sample()
    b["dns"]["results"][1]["ok"] = False
    assert by_topic(compare_reports(a,b), "DNS")[0]["status"] == "changed"


def test_dns_incomplete_servers_note():
    a, b = sample(), sample()
    b["dns"]["results"].pop()
    assert any("серверов" in text for text in compare_reports(a,b)["limitations"])


def test_dns_no_common_server():
    a, b = sample(), sample()
    b["dns"]["results"] = [{"server": "9.9.9.9", "ok": True, "ipv4": ["8.8.8.8"]}]
    assert by_topic(compare_reports(a,b), "DNS")[0]["status"] == "not_comparable"


def test_route_change_interface():
    a, b = sample(), sample()
    b["route"]["best"]["interface"] = "10.255.104.151"
    assert by_topic(compare_reports(a,b), "Маршрут")[0]["status"] == "changed"


def test_route_different_destination_not_comparable():
    a, b = sample(), sample()
    b["route"]["destination"] = "8.8.8.8"
    assert by_topic(compare_reports(a,b), "Маршрут")[0]["status"] == "not_comparable"


def test_route_from_missing_to_known():
    a, b = sample(), sample()
    a["route"]["best"] = None
    assert by_topic(compare_reports(a,b), "Маршрут")[0]["status"] == "changed"


def test_vpn_adapter_added():
    a, b = sample(), sample()
    b["adapters"].append({"name":"VPN-new", "vpn_candidate":True, "is_up":True, "ipv4":[]})
    assert by_topic(compare_reports(a,b), "Адаптеры")[0]["status"] == "changed"


def test_vpn_adapter_down():
    a, b = sample(), sample()
    b["adapters"][0]["is_up"] = False
    assert by_topic(compare_reports(a,b), "Адаптеры")[0]["status"] == "changed"


def test_no_proof_of_causation():
    result = compare_reports(sample(), sample())
    assert "не доказывают" in result["limitations"][0]
