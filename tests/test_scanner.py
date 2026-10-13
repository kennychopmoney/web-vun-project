import subprocess
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from app import app
from scanner import (
    NMAP_IMAGE,
    RECON_PORTS,
    ZAP_IMAGE,
    _NoRedirectHandler,
    analyze_headers,
    analyze_html,
    check_reflected_input,
    run_nmap_scan,
    run_reconnaissance,
    run_zap_baseline,
)


class FakeResponse:
    headers = {"Content-Type": "text/html; charset=utf-8"}

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size=-1):
        return self.body


class FakeOpener:
    def __init__(self):
        self.request_count = 0

    def open(self, request, timeout):
        self.request_count += 1
        self.assert_timeout = timeout
        query = parse_qs(urlparse(request.full_url).query)
        marker_value = query["q"][0]
        return FakeResponse(f"<html>{marker_value}</html>".encode("ascii"))


class ScannerTests(unittest.TestCase):
    def test_missing_security_headers_returns_findings(self):
        findings = analyze_headers({}, "https://example.com")
        titles = {item["title"] for item in findings}
        self.assertIn("Missing HSTS header", titles)
        self.assertIn("Missing Content-Security-Policy header", titles)

    def test_inline_javascript_is_detected(self):
        findings = analyze_html(
            "<script>alert('hi')</script><a href=\"javascript:alert(1)\">Click</a>",
            "https://example.com",
        )
        titles = {item["title"] for item in findings}
        self.assertIn("Inline script or JavaScript execution", titles)

    def test_missing_cookie_flags_are_detected(self):
        findings = analyze_headers({"Set-Cookie": "sessionid=secret-value; Path=/"}, "https://example.com")
        titles = {item["title"] for item in findings}
        self.assertIn("Cookies are missing HttpOnly protection", titles)
        self.assertIn("Cookies are missing Secure flags", titles)
        self.assertIn("Cookies are missing SameSite protection", titles)
        self.assertTrue(all("secret-value" not in item["evidence"] for item in findings))

    def test_frame_ancestors_directive_protects_against_framing(self):
        findings = analyze_headers(
            {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"},
            "https://example.com",
        )
        titles = {item["title"] for item in findings}
        self.assertNotIn("Missing frame protection", titles)

    def test_open_redirect_logic_is_detected(self):
        findings = analyze_html(
            "<script>window.location='https://evil.example/?next=' + url;</script>",
            "https://example.com",
        )
        titles = {item["title"] for item in findings}
        self.assertIn("Potential open redirect or client-side redirect logic", titles)
        self.assertTrue(all(item["remediation"] for item in findings))
        self.assertTrue(all(item["confidence"] for item in findings))

    @patch("scanner.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))])
    @patch("scanner.build_opener")
    def test_active_reflection_check_sends_only_harmless_query_marker(self, mock_build_opener, _mock_dns):
        opener = FakeOpener()
        mock_build_opener.return_value = opener

        findings = check_reflected_input(
            "https://test.example.com/search?q=sample",
            {"test.example.com"},
        )

        self.assertEqual(opener.request_count, 1)
        self.assertEqual(opener.assert_timeout, 5)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "Input marker reflected in HTML response")
        self.assertIn("query parameter 'q'", findings[0]["evidence"])
        self.assertNotIn("webvun", findings[0]["evidence"])

    def test_active_check_rejects_non_allowlisted_host(self):
        with self.assertRaisesRegex(ValueError, "exact hostname"):
            check_reflected_input(
                "https://not-allowed.example/search?q=sample",
                {"test.example.com"},
            )

    def test_active_check_rejects_more_than_five_parameters(self):
        with patch("scanner.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))]):
            with self.assertRaisesRegex(ValueError, "limited to five"):
                check_reflected_input(
                    "https://test.example.com/search?a=1&b=2&c=3&d=4&e=5&f=6",
                    {"test.example.com"},
                )

    def test_active_scan_redirect_handler_does_not_follow(self):
        self.assertIsNone(
            _NoRedirectHandler().redirect_request(None, None, 302, "Found", {}, "https://other.example/")
        )

    def test_api_requires_authorization_confirmation_for_active_checks(self):
        with app.test_client() as client:
            response = client.post(
                "/api/scan",
                json={"url": "https://test.example.com/search?q=sample", "active": True},
            )
        self.assertEqual(response.status_code, 403)
        self.assertIn("authorization", response.get_json()["error"].lower())

    @patch("scanner.socket.create_connection", side_effect=ConnectionRefusedError)
    @patch("scanner._resolve_public_addresses", return_value=["93.184.216.34"])
    @patch(
        "scanner.socket.getaddrinfo",
        return_value=[(None, None, None, None, ("93.184.216.34", 443))],
    )
    def test_recon_checks_only_fixed_web_ports(self, _mock_dns, _mock_resolve, mock_connect):
        results = run_reconnaissance("https://test.example.com/", {"test.example.com"})

        self.assertEqual([item["port"] for item in results["port_results"]], list(RECON_PORTS))
        self.assertEqual(mock_connect.call_count, len(RECON_PORTS))
        self.assertTrue(all(item["status"] == "closed_or_filtered" for item in results["port_results"]))
        self.assertFalse(results["http"]["redirects_followed"])
        self.assertIsNone(results["tls"])

    @patch("scanner.scan_url")
    def test_api_requires_authorization_for_reconnaissance(self, mock_scan):
        with app.test_client() as client:
            response = client.post(
                "/api/scan",
                json={"url": "https://test.example.com/", "reconnaissance": True},
            )
        self.assertEqual(response.status_code, 403)
        mock_scan.assert_not_called()

    @patch("scanner._run_scanner_container")
    @patch(
        "scanner.socket.getaddrinfo",
        return_value=[(None, None, None, None, ("93.184.216.34", 443))],
    )
    def test_nmap_uses_validated_ip_and_parses_open_ports(self, _mock_dns, mock_docker):
        mock_docker.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                '<nmaprun><host><ports><port protocol="tcp" portid="443">'
                '<state state="open" reason="syn-ack"/><service name="https"/>'
                '</port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
            ),
            stderr="",
        )

        result = run_nmap_scan("https://test.example.com/", {"test.example.com"})

        self.assertEqual(result["target_address"], "93.184.216.34")
        self.assertEqual(
            result["open_ports"],
            [{"port": 443, "protocol": "tcp", "service": "https", "reason": "syn-ack"}],
        )
        self.assertEqual(mock_docker.call_args.args[0], NMAP_IMAGE)
        self.assertIn("20", mock_docker.call_args.args[1])
        self.assertIn("--unprivileged", mock_docker.call_args.args[1])

    @patch("scanner._run_scanner_container")
    @patch(
        "scanner.socket.getaddrinfo",
        return_value=[(None, None, None, None, ("93.184.216.34", 443))],
    )
    def test_zap_parses_passive_alert_and_excludes_query_values(self, _mock_dns, mock_docker):
        mock_docker.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "ZAP baseline starting\n"
                '{"site":[{"alerts":[{"riskcode":"2","confidence":"3",'
                '"alert":"Header review","desc":"Description","solution":"Remediation",'
                '"reference":"https://example.org/docs","instances":[{}]}]}]}'
            ),
            stderr="",
        )

        result = run_zap_baseline(
            "https://test.example.com/path?token=secret#fragment",
            {"test.example.com"},
        )

        self.assertEqual(result["alerts"][0]["severity"], "medium")
        self.assertEqual(result["alerts"][0]["confidence"], "High")
        self.assertEqual(result["summary"], {"medium": 1})
        self.assertEqual(mock_docker.call_args.args[0], ZAP_IMAGE)
        self.assertEqual(mock_docker.call_args.args[1][2], "https://test.example.com/path")
        self.assertNotIn("secret", str(result))

    @patch("scanner.shutil.which", return_value=None)
    def test_docker_scan_fails_clearly_when_cli_is_missing(self, _mock_which):
        from scanner import _run_scanner_container

        with self.assertRaisesRegex(RuntimeError, "Docker CLI was not found"):
            _run_scanner_container("webvun/nmap:1", [], 10, "256m", "0.5")

    @patch("scanner.subprocess.run")
    @patch("scanner.shutil.which", return_value="C:\\Program Files\\Docker\\docker.exe")
    def test_docker_runner_uses_restricted_container_options(self, _mock_which, mock_run):
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr=""),
        ]
        from scanner import _run_scanner_container

        result = _run_scanner_container("webvun/nmap:1", ["-sT", "93.184.216.34"], 45, "256m", "0.5")

        command = mock_run.call_args_list[1].args[0]
        self.assertEqual(result.stdout, "ok")
        self.assertIn("--pull=never", command)
        self.assertIn("--network=bridge", command)
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop=ALL", command)
        self.assertNotIn("--privileged", command)
        self.assertFalse(any(argument in {"-v", "--volume"} for argument in command))

    @patch("scanner.scan_url")
    def test_api_requires_authorization_for_docker_scan(self, mock_scan):
        with app.test_client() as client:
            response = client.post(
                "/api/scan",
                json={"url": "https://test.example.com/", "nmap": True},
            )
        self.assertEqual(response.status_code, 403)
        mock_scan.assert_not_called()

    def test_api_rejects_combined_reflection_and_docker_scan_modes(self):
        with patch("app.ACTIVE_ALLOWED_HOSTS", {"test.example.com"}):
            with patch("scanner.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))]):
                with app.test_client() as client:
                    response = client.post(
                        "/api/scan",
                        json={
                            "url": "https://test.example.com/search?q=sample",
                            "active": True,
                            "nmap": True,
                            "authorized": True,
                        },
                    )
        self.assertEqual(response.status_code, 400)
        self.assertIn("separately", response.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
