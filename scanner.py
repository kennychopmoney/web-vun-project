import re
from typing import Dict, List
from urllib.parse import urlparse
from urllib.request import Request, urlopen

SEVERITY_WEIGHT = {
    "info": 0,
    "low": 5,
    "medium": 12,
    "high": 20,
    "critical": 30,
}


def _ensure_valid_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Please provide a valid URL such as https://example.com")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported")
    return url.rstrip("/")


def _extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return "Untitled page"
    return re.sub(r"\s+", " ", match.group(1)).strip() or "Untitled page"


def _fetch_page(url: str) -> Dict:
    request = Request(url, headers={"User-Agent": "WebVunScanner/1.0"})
    with urlopen(request, timeout=10) as response:
        content = response.read().decode("utf-8", errors="replace")
        headers = {str(key): str(value) for key, value in response.headers.items()}
        return {
            "url": response.geturl(),
            "status_code": getattr(response, "status", 200),
            "content_type": headers.get("Content-Type", "unknown"),
            "headers": headers,
            "html": content,
        }


def _add_finding(findings: List[Dict], severity: str, title: str, description: str, evidence: str = "") -> None:
    findings.append(
        {
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence,
        }
    )


def analyze_headers(headers: Dict[str, str], target_url: str) -> List[Dict]:
    findings: List[Dict] = []
    lower_headers = {key.lower(): value for key, value in headers.items()}
    scheme = urlparse(target_url).scheme

    if scheme == "https" and "strict-transport-security" not in lower_headers:
        _add_finding(
            findings,
            "medium",
            "Missing HSTS header",
            "The site does not enforce HTTPS for all future requests.",
            "Strict-Transport-Security is absent.",
        )

    if "content-security-policy" not in lower_headers:
        _add_finding(
            findings,
            "medium",
            "Missing Content-Security-Policy header",
            "Without a CSP, browsers can execute unexpected scripts or load untrusted content.",
            "Content-Security-Policy is missing.",
        )

    if "x-frame-options" not in lower_headers and "content-security-policy" not in lower_headers:
        _add_finding(
            findings,
            "medium",
            "Missing frame protection",
            "The page may be embedded in a malicious site via clickjacking.",
            "X-Frame-Options and CSP frame-ancestors are not present.",
        )

    if "x-content-type-options" not in lower_headers:
        _add_finding(
            findings,
            "low",
            "Missing X-Content-Type-Options",
            "The browser may try to interpret files as different content types.",
            "X-Content-Type-Options is missing.",
        )

    if "referrer-policy" not in lower_headers:
        _add_finding(
            findings,
            "low",
            "Missing Referrer-Policy",
            "Sensitive URLs may leak in the Referer header when users navigate away.",
            "Referrer-Policy is absent.",
        )

    set_cookie_values = [value for key, value in lower_headers.items() if key == "set-cookie"]
    for cookie_value in set_cookie_values:
        cookie_text = cookie_value.lower()
        if "httponly" not in cookie_text:
            _add_finding(
                findings,
                "medium",
                "Cookies are missing HttpOnly protection",
                "Session cookies can be read by client-side scripts if HttpOnly is not enabled.",
                cookie_value,
            )
        if scheme == "https" and "secure" not in cookie_text:
            _add_finding(
                findings,
                "medium",
                "Cookies are missing Secure flags",
                "Session cookies should only be sent over encrypted connections.",
                cookie_value,
            )
        if "samesite" not in cookie_text:
            _add_finding(
                findings,
                "low",
                "Cookies are missing SameSite protection",
                "Without SameSite controls, browsers may send cookies in cross-site requests.",
                cookie_value,
            )

    return findings


def analyze_html(html: str, target_url: str = "") -> List[Dict]:
    findings: List[Dict] = []
    lowered = html.lower()

    if re.search(r"<script\b|on\w+=|javascript:\s*", lowered):
        _add_finding(
            findings,
            "high",
            "Inline script or JavaScript execution",
            "The page contains inline JavaScript or javascript: URLs, which creates script injection risk.",
            "Inline script or javascript: URL detected.",
        )

    if re.search(r"<iframe|<object|<embed", lowered):
        _add_finding(
            findings,
            "medium",
            "Embedded active content",
            "The page allows external plugins or frames, which may be abused for phishing or tracking.",
            "Active embedded element found in markup.",
        )

    if "https://" in target_url and re.search(r"src=[\"']?http://|href=[\"']?http://", html, flags=re.IGNORECASE):
        _add_finding(
            findings,
            "medium",
            "Mixed-content resources",
            "The page loads insecure HTTP resources while served over HTTPS.",
            "An HTTP resource reference was detected.",
        )

    if re.search(r"<input[^>]*type=['\"]?password['\"]?", html, flags=re.IGNORECASE):
        _add_finding(
            findings,
            "info",
            "Password field detected",
            "Password inputs were found on the page; confirm the form is protected with a secure flow and CSRF protection.",
            "Password input field detected.",
        )

    form_matches = re.findall(r"<form\b([^>]*)>", html, flags=re.IGNORECASE | re.DOTALL)
    for form_attrs in form_matches:
        method_match = re.search(r"method\s*=\s*['\"]?([a-z]+)", form_attrs, flags=re.IGNORECASE)
        method = (method_match.group(1).upper() if method_match else "GET").upper()
        has_csrf_token = bool(re.search(r"(csrf|authenticity|xsrf|_token|nonce)", form_attrs, flags=re.IGNORECASE))
        if method in {"POST", "PUT", "PATCH", "DELETE"} and not has_csrf_token and re.search(r"<input[^>]*type=['\"]?password['\"]?", html, flags=re.IGNORECASE):
            _add_finding(
                findings,
                "medium",
                "Form may be missing CSRF protection",
                "A sensitive form appears to submit data without a CSRF token or similar validation.",
                "A password-bearing form is using a state-changing method without a visible CSRF control.",
            )
            break

    if re.search(r"(window\s*\.\s*location|document\s*\.\s*location|location\s*\.\s*href|window\.open\s*\()", lowered):
        _add_finding(
            findings,
            "medium",
            "Potential open redirect or client-side redirect logic",
            "Client-side redirect logic can be abused to send users to attacker-controlled destinations.",
            "Redirect flow detected in JavaScript.",
        )

    if re.search(r"(?:redirect|returnurl|return_url|next|url)\s*[:=]\s*[\"']?https?://", lowered):
        _add_finding(
            findings,
            "medium",
            "Potential URL parameter redirect handling",
            "The page appears to rely on a URL parameter to determine where to redirect the user.",
            "A target URL or redirect parameter was detected in markup or script.",
        )

    return findings


def scan_url(url: str) -> Dict:
    normalized_url = _ensure_valid_url(url)
    page = _fetch_page(normalized_url)
    findings = analyze_headers(page["headers"], normalized_url)
    findings.extend(analyze_html(page["html"], normalized_url))

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        summary[item["severity"]] = summary.get(item["severity"], 0) + 1

    risk_score = sum(SEVERITY_WEIGHT.get(item["severity"], 0) for item in findings)
    risk_score = min(risk_score, 100)

    result = {
        "url": page["url"],
        "status_code": page["status_code"],
        "content_type": page["content_type"],
        "title": _extract_title(page["html"]),
        "server": page["headers"].get("Server", "Unknown"),
        "risk_score": risk_score,
        "summary": summary,
        "findings": findings,
    }
    return result
