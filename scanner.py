import ipaddress
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from json import JSONDecoder, JSONDecodeError
from typing import Dict, List
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

SEVERITY_WEIGHT = {
    "info": 0,
    "low": 5,
    "medium": 12,
    "high": 20,
    "critical": 30,
}
RECON_PORTS = (80, 443, 8080, 8443)
NMAP_IMAGE = "webvun/nmap:1"
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
NMAP_PORT_LIMIT = 20

FINDING_GUIDANCE = {
    "Missing HSTS header": (
        "High",
        "After confirming the site and all subdomains support HTTPS, send a Strict-Transport-Security header "
        "with an appropriate max-age. Add includeSubDomains or preload only after validating their impact.",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
    ),
    "Missing Content-Security-Policy header": (
        "High",
        "Define a Content-Security-Policy starting with a report-only policy, then restrict script, object, "
        "base, and frame sources. Avoid unsafe-inline where possible and test before enforcement.",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy",
    ),
    "Missing frame protection": (
        "High",
        "Set Content-Security-Policy frame-ancestors to the required trusted origins, or use "
        "X-Frame-Options for older browser compatibility.",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",
    ),
    "Missing X-Content-Type-Options": (
        "High",
        "Send X-Content-Type-Options: nosniff and ensure each response has the correct Content-Type.",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options",
    ),
    "Missing Referrer-Policy": (
        "High",
        "Set a Referrer-Policy such as strict-origin-when-cross-origin, or a stricter policy if the application requires it.",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy",
    ),
    "Cookies are missing HttpOnly protection": (
        "High",
        "Set HttpOnly on session cookies that do not need to be read by browser JavaScript.",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie#httponly",
    ),
    "Cookies are missing Secure flags": (
        "High",
        "Set Secure on cookies served over HTTPS so browsers do not send them over plaintext HTTP.",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie#secure",
    ),
    "Cookies are missing SameSite protection": (
        "High",
        "Set SameSite=Lax or Strict where compatible. For cross-site use cases, use SameSite=None together with Secure "
        "and implement appropriate CSRF defenses.",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value",
    ),
    "Inline script or JavaScript execution": (
        "Low",
        "Inline JavaScript is not by itself proof of a vulnerability. Prefer external scripts or CSP nonces/hashes, "
        "and use context-aware output encoding wherever untrusted data is rendered.",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ),
    "Embedded active content": (
        "Low",
        "Review each embedded frame or plugin. Restrict frame sources with CSP and apply a restrictive sandbox "
        "attribute to frames that do not need full privileges.",
        "https://developer.mozilla.org/docs/Web/HTML/Element/iframe#sandbox",
    ),
    "Mixed-content resources": (
        "High",
        "Serve every script, stylesheet, image, and other resource over HTTPS. Update hard-coded HTTP URLs and "
        "verify third-party resources support HTTPS.",
        "https://developer.mozilla.org/docs/Web/Security/Mixed_content",
    ),
    "Password field detected": (
        "Low",
        "Confirm credentials are submitted only over HTTPS, use secure session cookies, and apply server-side "
        "CSRF protections to state-changing authenticated actions.",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    ),
    "Form may be missing CSRF protection": (
        "Low",
        "Verify the form is protected server-side with a per-session or per-request anti-CSRF token, and use "
        "SameSite cookies as defense in depth. This static check can miss tokens added dynamically.",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    ),
    "Potential open redirect or client-side redirect logic": (
        "Low",
        "Do not redirect directly to user-supplied URLs. Allowlist destinations or accept only validated relative "
        "paths, and test the redirect endpoint with untrusted input.",
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    ),
    "Potential URL parameter redirect handling": (
        "Low",
        "Validate redirect destinations against an explicit allowlist or map short server-side identifiers to "
        "approved destinations; reject arbitrary absolute URLs.",
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    ),
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


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def _fetch_page(
    url: str,
    follow_redirects: bool = True,
    max_bytes: int | None = None,
    return_redirect_response: bool = False,
) -> Dict:
    request = Request(url, headers={"User-Agent": "WebVunScanner/1.0"})
    opener = build_opener() if follow_redirects else build_opener(_NoRedirectHandler)
    try:
        response_context = opener.open(request, timeout=10)
    except HTTPError as exc:
        if not follow_redirects and 300 <= exc.code < 400 and return_redirect_response:
            response_context = exc
        elif not follow_redirects and 300 <= exc.code < 400:
            raise ValueError("Active scans do not follow redirects. Scan the authorized destination directly.") from exc
        else:
            raise

    with response_context as response:
        content_bytes = response.read(max_bytes + 1) if max_bytes is not None else response.read()
        if max_bytes is not None and len(content_bytes) > max_bytes:
            raise ValueError(f"Response exceeded the {max_bytes // 1_000_000} MB safety limit.")
        content = content_bytes.decode("utf-8", errors="replace")
        headers = {str(key): str(value) for key, value in response.headers.items()}
        return {
            "url": response.geturl(),
            "status_code": getattr(response, "status", getattr(response, "code", 200)),
            "content_type": headers.get("Content-Type", "unknown"),
            "headers": headers,
            "html": content,
        }


def _resolve_public_addresses(hostname: str, port: int | None) -> List[str]:
    try:
        addresses = sorted(
            {entry[4][0] for entry in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)}
        )
    except OSError as exc:
        raise ValueError(f"Could not resolve the allowlisted host: {exc}") from exc

    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("Active checks require an allowlisted hostname that resolves only to public IP addresses.")
    return addresses


def _validate_active_scope(
    url: str,
    allowed_hosts: set[str],
    require_query: bool = True,
) -> tuple[str, str, List[str]]:
    normalized_url = _ensure_valid_url(url)
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower().rstrip(".")

    if parsed.username or parsed.password:
        raise ValueError("Active checks do not allow URLs containing embedded credentials.")
    if hostname not in allowed_hosts:
        raise ValueError(
            "Active checks are disabled for this host. Add its exact hostname to "
            "WEBVUN_ACTIVE_ALLOWED_HOSTS on the server."
        )
    if require_query and not parsed.query:
        raise ValueError("Add one or more query parameters to the URL to run reflected-input checks.")

    return normalized_url, hostname, _resolve_public_addresses(hostname, parsed.port)


def _validate_active_target(url: str, allowed_hosts: set[str], require_query: bool = True) -> str:
    return _validate_active_scope(url, allowed_hosts, require_query)[0]


def _read_tls_certificate(hostname: str, address: str, port: int) -> Dict:
    tls_context = ssl.create_default_context()
    with socket.create_connection((address, port), timeout=1) as raw_socket:
        with tls_context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
            certificate = tls_socket.getpeercert()
            expires_at = certificate.get("notAfter")
            expiry = (
                datetime.fromtimestamp(ssl.cert_time_to_seconds(expires_at), timezone.utc).isoformat()
                if expires_at
                else None
            )
            names = [
                value
                for name_type, value in certificate.get("subjectAltName", [])
                if name_type == "DNS"
            ][:20]
            return {
                "tls_version": tls_socket.version(),
                "cipher": tls_socket.cipher()[0] if tls_socket.cipher() else None,
                "certificate_subject_alt_names": names,
                "certificate_expires_at": expiry,
            }


def run_reconnaissance(url: str, allowed_hosts: set[str]) -> Dict:
    normalized_url, hostname, addresses = _validate_active_scope(
        url,
        allowed_hosts,
        require_query=False,
    )
    return _run_reconnaissance_validated(normalized_url, hostname, addresses)


def _run_reconnaissance_validated(normalized_url: str, hostname: str, addresses: List[str]) -> Dict:
    parsed = urlsplit(normalized_url)

    port_results = []
    for address in addresses[:4]:
        for port in RECON_PORTS:
            try:
                with socket.create_connection((address, port), timeout=0.5):
                    port_results.append({"address": address, "port": port, "status": "open"})
            except (TimeoutError, ConnectionRefusedError, OSError):
                port_results.append({"address": address, "port": port, "status": "closed_or_filtered"})

    tls_details = None
    tls_port = parsed.port if parsed.port in {443, 8443} else (443 if parsed.scheme == "https" else None)
    if tls_port is not None:
        tls_address = next(
            (address for address in addresses if any(result["address"] == address and result["port"] == tls_port and result["status"] == "open" for result in port_results)),
            None,
        )
        if tls_address:
            try:
                tls_details = _read_tls_certificate(hostname, tls_address, tls_port)
            except (OSError, ssl.SSLError, ValueError) as exc:
                tls_details = {"error": f"TLS details unavailable: {exc}"}

    return {
        "hostname": hostname,
        "addresses": addresses,
        "checked_ports": list(RECON_PORTS),
        "port_results": port_results,
        "tls": tls_details,
        "http": {
            "requested_url": normalized_url,
            "redirects_followed": False,
        },
        "limits": {
            "maximum_addresses_checked": 4,
            "connect_timeout_seconds": 0.5,
        },
    }


def _run_scanner_container(
    image: str,
    container_args: List[str],
    timeout_seconds: int,
    memory: str,
    cpu_limit: str,
    extra_args: List[str] | None = None,
    accepted_exit_codes: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess:
    docker_path = shutil.which("docker")
    if docker_path is None:
        raise RuntimeError("Docker is required for Nmap/ZAP scans but the Docker CLI was not found.")

    try:
        image_status = subprocess.run(
            [docker_path, "image", "inspect", image],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Timed out while checking for the local scanner image.") from exc
    if image_status.returncode != 0:
        raise RuntimeError(
            f"Required Docker image '{image}' is not available locally. Follow the README setup instructions first."
        )

    container_name = f"webvun-scan-{secrets.token_hex(8)}"
    command = [
        docker_path,
        "run",
        "--rm",
        f"--name={container_name}",
        "--pull=never",
        "--network=bridge",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=128",
        f"--memory={memory}",
        f"--cpus={cpu_limit}",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=128m",
    ]
    command.extend(extra_args or [])
    command.extend([image, *container_args])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        cleanup = subprocess.run(
            [docker_path, "container", "rm", "--force", container_name],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if cleanup.returncode != 0 and "no such container" not in cleanup.stderr.lower():
            detail = cleanup.stderr.strip()[-500:] or "No diagnostic output was produced."
            raise RuntimeError(f"Could not clean up timed-out scanner container: {detail}") from exc
        raise RuntimeError(f"Docker scanner exceeded its {timeout_seconds}-second time limit.") from exc

    if result.returncode not in accepted_exit_codes:
        detail = result.stderr.strip()[-1000:] or "No diagnostic output was produced."
        raise RuntimeError(f"Docker scanner failed with exit code {result.returncode}: {detail}")
    return result


def run_nmap_scan(url: str, allowed_hosts: set[str]) -> Dict:
    _, hostname, addresses = _validate_active_scope(
        url,
        allowed_hosts,
        require_query=False,
    )
    target_address = addresses[0]
    nmap_arguments = [
        "-sT",
        "-Pn",
        "-n",
        "--unprivileged",
        "--top-ports",
        str(NMAP_PORT_LIMIT),
        "--open",
        "--reason",
        "--max-retries",
        "1",
        "--host-timeout",
        "30s",
        "--scan-delay",
        "100ms",
        "-oX",
        "-",
    ]
    if ipaddress.ip_address(target_address).version == 6:
        nmap_arguments.insert(0, "-6")
    result = _run_scanner_container(
        NMAP_IMAGE,
        [*nmap_arguments, target_address],
        timeout_seconds=45,
        memory="256m",
        cpu_limit="0.5",
    )
    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError as exc:
        raise RuntimeError("Nmap returned invalid XML output.") from exc

    open_ports = []
    for port_node in root.findall("./host/ports/port"):
        state_node = port_node.find("state")
        if state_node is None or state_node.get("state") != "open":
            continue
        service_node = port_node.find("service")
        open_ports.append(
            {
                "port": int(port_node.get("portid", "0")),
                "protocol": port_node.get("protocol", "tcp"),
                "service": service_node.get("name", "unknown") if service_node is not None else "unknown",
                "reason": state_node.get("reason", "unknown"),
            }
        )

    finished = root.find("./runstats/finished")
    return {
        "hostname": hostname,
        "target_address": target_address,
        "method": "TCP connect scan",
        "ports_scanned": NMAP_PORT_LIMIT,
        "open_ports": open_ports,
        "limitations": "No service-version detection, OS detection, UDP scan, scripts, or exploit checks were run.",
        "exit_status": finished.get("exit", "unknown") if finished is not None else "unknown",
    }


def _extract_zap_report(output: str) -> Dict:
    decoder = JSONDecoder()
    for index, character in enumerate(output):
        if character != "{":
            continue
        try:
            report, _ = decoder.raw_decode(output[index:])
        except JSONDecodeError:
            continue
        if isinstance(report, dict) and isinstance(report.get("site"), list):
            return report
    raise RuntimeError("ZAP did not produce a parseable JSON baseline report.")


def run_zap_baseline(url: str, allowed_hosts: set[str]) -> Dict:
    normalized_url, hostname, addresses = _validate_active_scope(
        url,
        allowed_hosts,
        require_query=False,
    )
    parsed = urlsplit(normalized_url)
    target_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    output = _run_scanner_container(
        ZAP_IMAGE,
        [
            "zap-baseline.py",
            "-t",
            target_url,
            "-m",
            "1",
            "-T",
            "3",
            "-I",
            "-J",
            "/dev/stdout",
        ],
        timeout_seconds=240,
        memory="1g",
        cpu_limit="1",
        extra_args=[
            "--add-host",
            f"{hostname}:{addresses[0]}",
            "-e",
            "HOME=/tmp",
            "-e",
            "ZAP_HOME=/tmp/zap",
        ],
        accepted_exit_codes=(0, 1),
    )
    report = _extract_zap_report(output.stdout)

    confidence_labels = {"0": "False positive", "1": "Low", "2": "Medium", "3": "High"}
    risk_labels = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}
    alerts = []
    for site in report["site"]:
        for alert in site.get("alerts", []):
            risk = str(alert.get("riskcode", "0"))
            alerts.append(
                {
                    "severity": risk_labels.get(risk, "info"),
                    "title": str(alert.get("alert", "ZAP alert"))[:300],
                    "description": str(alert.get("desc", ""))[:3000],
                    "evidence": f"Instances: {len(alert.get('instances', []))}",
                    "confidence": confidence_labels.get(str(alert.get("confidence", "0")), "Unknown"),
                    "remediation": str(alert.get("solution", "Review the ZAP passive alert and verify applicability."))[:3000],
                    "reference": str(alert.get("reference", ""))[:1000],
                    "source": "OWASP ZAP baseline",
                }
            )
            if len(alerts) >= 100:
                break
        if len(alerts) >= 100:
            break

    summary: Dict[str, int] = {}
    for alert in alerts:
        summary[alert["severity"]] = summary.get(alert["severity"], 0) + 1
    return {
        "hostname": hostname,
        "profile": "OWASP ZAP baseline (spider + passive rules; no active attack scan)",
        "alerts": alerts,
        "summary": summary,
        "duration_limit_minutes": 1,
        "note": "The baseline spider can issue GET requests. Alerts are heuristic and need manual verification.",
    }


def check_reflected_input(url: str, allowed_hosts: set[str]) -> List[Dict]:
    target_url = _validate_active_target(url, allowed_hosts)
    return _check_reflected_input_validated(target_url)


def _check_reflected_input_validated(target_url: str) -> List[Dict]:
    parsed = urlsplit(target_url)
    parameters = parse_qsl(parsed.query, keep_blank_values=True)
    if len(parameters) > 5:
        raise ValueError("Active checks are limited to five query parameters per scan.")

    findings: List[Dict] = []
    opener = build_opener(_NoRedirectHandler)
    for index, (parameter_name, value) in enumerate(parameters):
        marker = f"webvun{secrets.token_hex(12)}"
        probed_parameters = list(parameters)
        probed_parameters[index] = (parameter_name, f"{value}{marker}")
        probe_url = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(probed_parameters), "")
        )
        request = Request(
            probe_url,
            headers={
                "User-Agent": "WebVunScanner/1.0 (authorized passive-impact check)",
                "Accept": "text/html",
            },
        )
        try:
            response_context = opener.open(request, timeout=5)
        except HTTPError as exc:
            if 300 <= exc.code < 400:
                raise ValueError(
                    "Active checks do not follow redirects. Verify the destination and scan it directly."
                ) from exc
            raise

        with response_context as response:
            content_type = response.headers.get("Content-Type", "")
            body = response.read(1_000_001)

        if len(body) > 1_000_000:
            raise ValueError("Active check response exceeded the 1 MB safety limit.")
        if "html" in content_type.lower() and marker.encode("ascii") in body:
            _add_finding(
                findings,
                "low",
                "Input marker reflected in HTML response",
                "A harmless unique marker supplied in a query parameter appeared in the HTML response. "
                "This does not confirm executable XSS; verify the output context and encoding manually.",
                f"Marker from query parameter '{parameter_name}' was present in the HTML response.",
            )

    return findings


def _add_finding(findings: List[Dict], severity: str, title: str, description: str, evidence: str = "") -> None:
    confidence, remediation, reference = FINDING_GUIDANCE.get(
        title,
        ("Low", "Review the evidence and verify the behavior in an authorized manual assessment.", ""),
    )
    findings.append(
        {
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence,
            "confidence": confidence,
            "remediation": remediation,
            "reference": reference,
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

    csp = lower_headers.get("content-security-policy", "")
    has_frame_ancestors = bool(re.search(r"(?:^|;)\s*frame-ancestors(?:\s|;|$)", csp, flags=re.IGNORECASE))
    if "x-frame-options" not in lower_headers and not has_frame_ancestors:
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
        cookie_parts = [part.strip() for part in cookie_value.split(";")]
        cookie_attributes = {part.split("=", 1)[0].strip().lower() for part in cookie_parts}
        if "httponly" not in cookie_attributes:
            _add_finding(
                findings,
                "medium",
                "Cookies are missing HttpOnly protection",
                "Session cookies can be read by client-side scripts if HttpOnly is not enabled.",
                f"{cookie_parts[0].split('=', 1)[0]}=[redacted]; {'; '.join(cookie_parts[1:])}",
            )
        if scheme == "https" and "secure" not in cookie_attributes:
            _add_finding(
                findings,
                "medium",
                "Cookies are missing Secure flags",
                "Session cookies should only be sent over encrypted connections.",
                f"{cookie_parts[0].split('=', 1)[0]}=[redacted]; {'; '.join(cookie_parts[1:])}",
            )
        if "samesite" not in cookie_attributes:
            _add_finding(
                findings,
                "low",
                "Cookies are missing SameSite protection",
                "Without SameSite controls, browsers may send cookies in cross-site requests.",
                f"{cookie_parts[0].split('=', 1)[0]}=[redacted]; {'; '.join(cookie_parts[1:])}",
            )

    return findings


def analyze_html(html: str, target_url: str = "") -> List[Dict]:
    findings: List[Dict] = []
    lowered = html.lower()

    if re.search(r"<script\b|on\w+=|javascript:\s*", lowered):
        _add_finding(
            findings,
            "info",
            "Inline script or JavaScript execution",
            "Inline JavaScript or javascript: URLs were observed. This is not proof of an exploitable injection vulnerability.",
            "Inline script or javascript: URL detected.",
        )

    if re.search(r"<iframe|<object|<embed", lowered):
        _add_finding(
            findings,
            "info",
            "Embedded active content",
            "An iframe, object, or embed element was observed. Review its source and restrictions; its presence alone is not a vulnerability.",
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
            "low",
            "Potential open redirect or client-side redirect logic",
            "Client-side redirect logic was observed. This heuristic does not confirm that untrusted destinations are accepted.",
            "Redirect flow detected in JavaScript.",
        )

    if re.search(r"(?:redirect|returnurl|return_url|next|url)\s*[:=]\s*[\"']?https?://", lowered):
        _add_finding(
            findings,
            "low",
            "Potential URL parameter redirect handling",
            "A redirect-like URL pattern was observed. Confirm whether the application accepts attacker-controlled destinations.",
            "A target URL or redirect parameter was detected in markup or script.",
        )

    return findings


def scan_url(
    url: str,
    active: bool = False,
    allowed_hosts: set[str] | None = None,
    reconnaissance: bool = False,
    nmap: bool = False,
    zap_baseline: bool = False,
) -> Dict:
    normalized_url = _ensure_valid_url(url)
    if active and (nmap or zap_baseline or reconnaissance):
        raise ValueError("Reflected-input checks must be run separately from reconnaissance or Docker scans.")
    active_modes = active or reconnaissance or nmap or zap_baseline
    if active_modes:
        if allowed_hosts is None:
            raise ValueError("Active checks are not configured on this server.")
        normalized_url = _validate_active_target(normalized_url, allowed_hosts, require_query=active)
    restricted_active_scan = active or reconnaissance or nmap or zap_baseline
    page = _fetch_page(
        normalized_url,
        follow_redirects=not restricted_active_scan,
        max_bytes=1_000_000 if restricted_active_scan else None,
        return_redirect_response=restricted_active_scan,
    )
    if zap_baseline and 300 <= page["status_code"] < 400:
        raise ValueError("ZAP baseline will not follow redirects. Enter the final authorized URL directly.")
    findings = analyze_headers(page["headers"], normalized_url)
    findings.extend(analyze_html(page["html"], normalized_url))

    active_checks = {"enabled": active, "probes_sent": 0}
    if active:
        active_findings = _check_reflected_input_validated(normalized_url)
        findings.extend(active_findings)
        active_checks["probes_sent"] = len(parse_qsl(urlparse(normalized_url).query, keep_blank_values=True))
    recon_results = run_reconnaissance(normalized_url, allowed_hosts or set()) if reconnaissance else None
    nmap_results = run_nmap_scan(normalized_url, allowed_hosts or set()) if nmap else None
    zap_results = run_zap_baseline(normalized_url, allowed_hosts or set()) if zap_baseline else None
    if zap_results:
        findings.extend(zap_results["alerts"])

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
        "active_checks": active_checks,
        "reconnaissance": recon_results,
        "nmap_scan": nmap_results,
        "zap_baseline": zap_results,
    }
    return result
