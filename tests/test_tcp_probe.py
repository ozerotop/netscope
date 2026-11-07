import pytest
from netscope.core.tcp_probe import check_tcp


class DummySocket:
    def __init__(self):
        self.timeout = None
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return None
    def settimeout(self, value):
        self.timeout = value
    def connect(self, endpoint):
        assert self.timeout == 2.5
        assert endpoint == ('151.101.0.223', 443)


def test_tcp_connect(monkeypatch):
    import netscope.core.tcp_probe as tcp
    monkeypatch.setattr(tcp.socket, 'getaddrinfo', lambda *args: [(2,1,6,'',('151.101.0.223',443))])
    monkeypatch.setattr(tcp.socket, 'socket', lambda *args: DummySocket())
    result = check_tcp('www.python.org', 443)
    assert result['ok'] is True
    assert result['ip'] == '151.101.0.223'


def test_invalid_tcp_port():
    with pytest.raises(ValueError):
        check_tcp('example.com', 0)
    with pytest.raises(ValueError):
        check_tcp('example.com', 65536)


def test_bad_tcp_target():
    with pytest.raises(ValueError):
        check_tcp('example.com; shutdown', 443)
