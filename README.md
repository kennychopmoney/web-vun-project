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

Only scan systems you own or have explicit permission to assess. This tool performs passive checks against the supplied page; it does not exploit vulnerabilities or confirm that a suspected issue is exploitable.

## Run it locally

```bash
cd "c:\Users\HomePC\Desktop\web-vun project"
python -m pip install -r requirements.txt
python app.py
```

Then open http://localhost:5000 in your browser.

## Run tests

```bash
cd "c:\Users\HomePC\Desktop\web-vun project"
python -m unittest discover -s tests -v
```
