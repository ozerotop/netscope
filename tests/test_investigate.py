import pytest
import netscope.core.investigate as mod


def test_investigate_report(monkeypatch):
    monkeypatch.setattr(mod, 'compare_dns', lambda domain, servers: {
        'domain': domain, 'answers_differ': True,
        'results': [dict(ok=True, ipv4=['1.1.1.1']), dict(ok=False, ipv4=[])]})
    monkeypatch.setattr(mod, 'inspect_route', lambda ip: {
        'best': dict(network='0.0.0.0/0', gateway='On-link', interface='172.19.0.1', metric=0, prefix_length=0),
        'ambiguous': False, 'error':'', 'matches':[], 'ok': True})
    monkeypatch.setattr(mod, 'check_tcp', lambda host, port: {'ok':True})
    from netscope.core.models import Adapter
    monkeypatch.setattr(mod, 'list_adapters', lambda: [Adapter('happ-xray', True, ['172.19.0.1'], True), Adapter('vpn17449', True, ['10.8.50.86'], True)])
    report = mod.investigate()
    assert len(report['vpn_candidates']) == 2
    assert any('CDN' in line for line in report['findings'])
    assert any('On-link' in line for line in report['findings'])


def test_investigate_rejects_params_before_io():
    with pytest.raises(ValueError):
        mod.investigate(dns_servers='1.1.1.1,hello')
    with pytest.raises(ValueError):
        mod.investigate(route_ip='no-ip')
