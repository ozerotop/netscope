import ipaddress
import struct
import pytest
from netscope.core.dns_compare import parse_dns_servers, make_dns_query, parse_dns_response, compare_dns


def fake_response(query: bytes, ips: list[str], flags=0x8180) -> bytes:
    transaction = query[:2]
    q = query[12:]
    answers = b''
    for ip in ips:
        answers += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + ipaddress.IPv4Address(ip).packed
    return transaction + struct.pack('!HHHHH', flags, 1, len(ips), 0, 0) + q + answers


def test_build_and_parse_response():
    query = make_dns_query('example.com', 1234)
    ips, message = parse_dns_response(fake_response(query, ['8.6.112.0', '8.47.69.0']), 1234)
    assert ips == ['8.47.69.0', '8.6.112.0']
    assert message == 'OK'


def test_reject_wrong_transaction():
    query = make_dns_query('example.com', 1234)
    with pytest.raises(ValueError):
        parse_dns_response(fake_response(query, ['1.1.1.1']), 9999)


def test_reject_truncated_or_invalid_pointer():
    query = make_dns_query('example.com', 17)
    with pytest.raises(ValueError):
        parse_dns_response(fake_response(query, ['1.1.1.1'])[:-1], 17)
    with pytest.raises(ValueError):
        parse_dns_response(query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + query[12:] + b'\xff\xff' + b'\x00'*10, 17)


def test_reject_bad_dns_servers():
    with pytest.raises(ValueError):
        parse_dns_servers('1.1.1.1,1.1.1.1')
    with pytest.raises(ValueError):
        parse_dns_servers('1.1.1.1,not-an-ip')
    with pytest.raises(ValueError):
        parse_dns_servers('1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4')


def test_comparison_differing_answers_is_only_hint(monkeypatch):
    monkeypatch.setattr('netscope.core.dns_compare.socket.getaddrinfo', lambda *args, **kwargs: [(None, None, None, None, ('2.2.2.2', 0))])
    monkeypatch.setattr('netscope.core.dns_compare.query_udp_a', lambda domain, server: {'server': server, 'ok': True, 'ipv4':['1.1.1.1'], 'detail':'OK', 'duration_ms':1})
    result = compare_dns('example.com', ['1.1.1.1'])
    assert result['answers_differ'] is True
    assert result['results'][0]['server'] == 'Windows (системный резолвер)'
