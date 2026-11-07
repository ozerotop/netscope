from netscope.core.http import check_https_windows, is_certificate_error
from netscope.core.models import Check
from netscope.core.diagnose import explain


def test_python_certificate_error_detected():
    assert is_certificate_error(Check(False, "<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED]>"))
    assert not is_certificate_error(Check(False, "Connection timeout"))


def test_windows_curl_verifies_without_insecure_flags(monkeypatch):
    def fake_run(args, timeout):
        assert args[0] == "curl.exe"
        assert "--insecure" not in args and "-k" not in args
        assert args[-1] == "https://example.com/"
        return (0, "200")
    monkeypatch.setattr("netscope.core.http.run_windows", fake_run)
    result = check_https_windows("https://example.com/")
    assert result.ok and "200" in result.detail


def test_windows_curl_failure_is_not_success(monkeypatch):
    monkeypatch.setattr("netscope.core.http.run_windows", lambda args, timeout: (60, "certificate verify failed\n000"))
    assert not check_https_windows("https://example.com/").ok


def test_windows_ok_python_failed_has_explanation():
    findings = explain(ping_received=4, dns_ok=True, https_ok=False, tls_error=True, windows_https_ok=True)
    assert any("Schannel" in text and "Do NOT disable" in text for text in findings)
