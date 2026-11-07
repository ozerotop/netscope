from netscope.core.routes import get_default_routes


def test_parse_default_route(monkeypatch):
    output = "Network Destination Netmask Gateway Interface Metric\n 0.0.0.0 0.0.0.0 192.168.1.1 192.168.1.50 25\n 127.0.0.0 255.0.0.0 On-link 127.0.0.1 331"
    monkeypatch.setattr("netscope.core.routes.run_windows", lambda args, timeout: (0, output))
    routes, note = get_default_routes()
    assert note == "OK"
    assert routes == [{"gateway": "192.168.1.1", "interface": "192.168.1.50", "metric": 25}]
