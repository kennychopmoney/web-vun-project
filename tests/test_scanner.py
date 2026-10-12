import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from app import app
from scanner import _NoRedirectHandler, analyze_headers, analyze_html, check_reflected_input


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


if __name__ == "__main__":
    unittest.main()
