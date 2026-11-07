from __future__ import annotations
from pathlib import Path
from flask import Flask, render_template, request, jsonify
from .core import analyze
from .dns_checks import domain_checks, verify_dkim

app = Flask(__name__, template_folder="../templates", static_folder="../static")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/api/analyze")
def api_analyze():
    upload = request.files.get("email_file")
    pasted = request.form.get("raw_headers", "").strip()
    if upload and upload.filename:
        raw_bytes = upload.read()
        raw = raw_bytes.decode("utf-8", "replace")
        filename = upload.filename
    elif pasted:
        raw_bytes = pasted.encode("utf-8")
        raw = pasted
        filename = "pasted-headers.txt"
    else:
        return jsonify({"error": "Upload a .eml/.txt file or paste email headers."}), 400

    result = analyze(raw)
    result["source_file"] = filename
    if request.form.get("dns") == "true":
        result["dns_checks"] = domain_checks(result["summary"]["from_domain"])
    if request.form.get("dkim") == "true" and filename.lower().endswith(".eml"):
        result["dkim_verification"] = verify_dkim(raw_bytes)
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
