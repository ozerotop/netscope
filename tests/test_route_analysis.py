import pytest
from netscope.core.route_analysis import parse_active_routes, matching_routes, inspect_route


ROUTES = '''
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       26.0.0.1    26.47.47.202   9257
          0.0.0.0          0.0.0.0      10.255.104.1  10.255.104.151  35
          0.0.0.0          0.0.0.0         On-link      172.19.0.1     0
       10.0.0.0       255.0.0.0        On-link      10.8.50.86    15
     10.2.3.0     255.255.255.0        10.8.50.1    10.8.50.86    77
     10.2.3.5   255.255.255.255        On-link       10.8.50.86   500
    10.3.0.0        255.0.255.0       10.8.50.1     10.8.50.86   8
===========================================================================
Persistent Routes:
 Network Address          Netmask  Gateway Address  Metric
  0.0.0.0                 0.0.0.0    1.2.3.4       1
'''


def test_parse_routes_only_valid_active_rows():
    routes = parse_active_routes(ROUTES)
    assert len(routes) == 6
    assert any(r.network == '10.2.3.0/24' and r.metric == 77 for r in routes)
    assert not any(r.gateway == '1.2.3.4' for r in routes)


def test_longest_prefix_then_metric():
    routes = parse_active_routes(ROUTES)
    assert matching_routes('10.2.3.5', routes)[0].network == '10.2.3.5/32'
    assert matching_routes('10.2.3.6', routes)[0].network == '10.2.3.0/24'
    assert matching_routes('10.99.0.1', routes)[0].network == '10.0.0.0/8'
    assert matching_routes('1.1.1.1', routes)[0].gateway == 'On-link'


def test_inspect_route_and_ties(monkeypatch):
    monkeypatch.setattr('netscope.core.route_analysis.run_windows', lambda args, timeout: (0, ROUTES))
    result = inspect_route('1.1.1.1')
    assert result['best']['gateway'] == 'On-link'
    assert result['best']['metric'] == 0
    assert result['ambiguous'] is False
    assert len(result['matches']) == 3


def test_invalid_address():
    with pytest.raises(ValueError):
        inspect_route('1.1.1.1 && whoami')


def test_tie_is_marked(monkeypatch):
    routes = '\n'.join(['0.0.0.0 0.0.0.0 10.0.0.1 10.0.0.2 25',
                        '0.0.0.0 0.0.0.0 10.1.1.1 10.1.1.2 25'])
    monkeypatch.setattr('netscope.core.route_analysis.run_windows', lambda args, timeout: (0, routes))
    assert inspect_route('9.9.9.9')['ambiguous'] is True
