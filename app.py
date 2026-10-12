from flask import Flask, jsonify, render_template, request

from scanner import scan_url

app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/scan")
def api_scan():
    payload = request.get_json(silent=True) or {}
    target = (payload.get("url") or "").strip()

    if not target:
        return jsonify({"error": "A URL is required."}), 400

    try:
        result = scan_url(target)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # pragma: no cover - defensive handling for runtime issues
        return jsonify({"error": f"Scan failed: {exc}"}), 500

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
