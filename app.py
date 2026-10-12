import os

from flask import Flask, jsonify, render_template, request

from scanner import scan_url

app = Flask(__name__)
ACTIVE_ALLOWED_HOSTS = {
    host.strip().lower().rstrip(".")
    for host in os.environ.get("WEBVUN_ACTIVE_ALLOWED_HOSTS", "").split(",")
    if host.strip()
}


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/scan")
def api_scan():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "The request body must be a JSON object."}), 400
    target_value = payload.get("url")
    if target_value is not None and not isinstance(target_value, str):
        return jsonify({"error": "The URL must be a string."}), 400
    target = (target_value or "").strip()
    active = payload.get("active") is True
    reconnaissance = payload.get("reconnaissance") is True
    authorized = payload.get("authorized") is True

    if not target:
        return jsonify({"error": "A URL is required."}), 400
    if (active or reconnaissance) and not authorized:
        return jsonify({"error": "Confirm explicit authorization before enabling active checks."}), 403

    try:
        result = scan_url(
            target,
            active=active,
            allowed_hosts=ACTIVE_ALLOWED_HOSTS,
            reconnaissance=reconnaissance,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # pragma: no cover - defensive handling for runtime issues
        return jsonify({"error": f"Scan failed: {exc}"}), 500

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
