import json
from html import escape
from pathlib import Path

def save_json(data: dict, path: str):
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

def save_html(data: dict, path: str):
    rows = "".join(f"<tr><td>{escape(x['severity'])}</td><td>{escape(x['detail'])}</td></tr>" for x in data.get("findings", []))
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>Email Forensic Report</title>
<style>body{{font:15px system-ui;max-width:1000px;margin:40px auto;padding:0 20px;background:#101827;color:#e8eef8}}
section{{background:#1b2940;padding:18px;border-radius:12px;margin:14px 0}}code,pre{{white-space:pre-wrap;overflow-wrap:anywhere}}
table{{width:100%;border-collapse:collapse}}td,th{{padding:9px;border-bottom:1px solid #40516a;text-align:left}}</style></head><body>
<h1>Email Header Analyzer PRO</h1><section><h2>Risk: {escape(data['risk_level'])} — {data['risk_score']}/100</h2>
<p>Subject: {escape(data['summary'].get('subject',''))}</p><p>From: {escape(data['summary'].get('from',''))}</p></section>
<section><h2>Findings</h2><table><tr><th>Severity</th><th>Finding</th></tr>{rows}</table></section>
<section><h2>Authentication results (as reported in headers)</h2><pre>{escape(json.dumps(data['authentication'], indent=2))}</pre></section>
<section><h2>IP addresses</h2><pre>{escape(json.dumps(data['ips'], indent=2))}</pre></section>
<section><h2>Limitations</h2><ul>{''.join('<li>'+escape(x)+'</li>' for x in data['limitations'])}</ul></section>
</body></html>"""
    Path(path).write_text(html, encoding="utf-8")
