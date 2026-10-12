# WebVun Scanner

A lightweight web vulnerability scanner built with Flask. It checks a target URL for common security weaknesses, including missing security headers, inline JavaScript, mixed-content risks, insecure cookies, and potential CSRF/redirect issues.

## Features

- Accepts public HTTP or HTTPS URLs
- Inspects HTTP security headers
- Detects inline JavaScript and javascript: links
- Reports mixed-content and embedded content issues
- Checks cookie protection flags such as HttpOnly, Secure, and SameSite
- Identifies likely CSRF gaps on sensitive forms
- Flags client-side redirect logic and redirect-parameter patterns
- Gives each finding remediation guidance, a detection-confidence indicator, and a technical reference
- Exports scan results as a JSON report
- Redacts cookie values from displayed evidence
- Uses non-intrusive checks; findings are heuristics and should be manually verified
- Shows a simple risk score and summary
- Includes a lightweight browser UI

Only scan systems you own or have explicit permission to assess. Passive checks are the default. Optional active reflected-input checks send harmless unique markers only in query parameters already present in the URL; they do not submit forms or follow redirects and do not confirm executable XSS.

Active checks require an exact hostname allowlist configured by the server operator, and an authorization confirmation in the UI. Set `WEBVUN_ACTIVE_ALLOWED_HOSTS` to a comma-separated list such as `test.example.com,staging.example.com`. Hosts resolving to non-public IP addresses are rejected. At most five query parameters are probed per scan, with a five-second request timeout and 1 MB response limit.

For an active check, include the query parameter(s) you want assessed in the target URL, for example `https://test.example.com/search?q=sample`. The scanner appends a random alphanumeric marker to each existing value and reports if that marker appears in an HTML response.

## Run it locally

```bash
cd "c:\Users\HomePC\Desktop\web-vun project"
python -m pip install -r requirements.txt
python app.py
```

Then open http://localhost:5000 in your browser.

### Enable active reflected-input checks

In PowerShell, configure the exact authorized hostnames before starting the app:

```powershell
$env:WEBVUN_ACTIVE_ALLOWED_HOSTS = "test.example.com,staging.example.com"
python app.py
```

Do not use a wildcard. The target URL must contain the query parameters you want tested. Active requests are read-only GETs, but still send traffic to the target; obtain permission and coordinate testing windows as required.

## Run tests

```bash
cd "c:\Users\HomePC\Desktop\web-vun project"
python -m unittest discover -s tests -v
```
