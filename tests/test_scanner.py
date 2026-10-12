import unittest

from scanner import analyze_headers, analyze_html


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
        findings = analyze_headers({"Set-Cookie": "sessionid=abc; Path=/"}, "https://example.com")
        titles = {item["title"] for item in findings}
        self.assertIn("Cookies are missing HttpOnly protection", titles)
        self.assertIn("Cookies are missing Secure flags", titles)
        self.assertIn("Cookies are missing SameSite protection", titles)

    def test_open_redirect_logic_is_detected(self):
        findings = analyze_html(
            "<script>window.location='https://evil.example/?next=' + url;</script>",
            "https://example.com",
        )
        titles = {item["title"] for item in findings}
        self.assertIn("Potential open redirect or client-side redirect logic", titles)


if __name__ == "__main__":
    unittest.main()
