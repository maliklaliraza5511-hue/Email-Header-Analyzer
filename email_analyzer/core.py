from __future__ import annotations
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from ipaddress import ip_address
from typing import Any
import re

SUSPICIOUS_TLDS = {".zip", ".mov", ".top", ".click", ".work", ".country", ".gq", ".tk"}

def parse_email(raw: str) -> dict[str, Any]:
    msg = Parser(policy=policy.default).parsestr(raw)
    headers = {k: msg.get_all(k, []) for k in msg.keys()}
    sender_name, sender_addr = parseaddr(msg.get("From", ""))
    return {
        "subject": str(msg.get("Subject", "")),
        "from": str(msg.get("From", "")),
        "from_address": sender_addr,
        "from_domain": sender_addr.rsplit("@", 1)[-1].lower() if "@" in sender_addr else "",
        "reply_to": str(msg.get("Reply-To", "")),
        "return_path": str(msg.get("Return-Path", "")),
        "date": str(msg.get("Date", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "received": [str(x) for x in msg.get_all("Received", [])],
        "authentication_results": [str(x) for x in msg.get_all("Authentication-Results", [])],
        "received_spf": [str(x) for x in msg.get_all("Received-SPF", [])],
        "dkim_signature_present": bool(msg.get_all("DKIM-Signature", [])),
        "headers": {k: [str(v) for v in vals] for k, vals in headers.items()},
        "body_present": bool(msg.get_body()),
    }

def extract_ips(text: str) -> list[str]:
    candidates = re.findall(r'(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9])|(?<![A-Za-z0-9])(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]+', text)
    out = []
    for candidate in candidates:
        try:
            ip = str(ip_address(candidate))
            if ip not in out:
                out.append(ip)
        except ValueError:
            pass
    return out

def analyze(raw: str) -> dict[str, Any]:
    parsed = parse_email(raw)
    all_headers = "\n".join(f"{k}: {'; '.join(v)}" for k, v in parsed["headers"].items())
    ips = extract_ips(all_headers)
    public_ips, private_ips = [], []
    for value in ips:
        obj = ip_address(value)
        (public_ips if obj.is_global else private_ips).append(value)

    auth_text = " ".join(parsed["authentication_results"] + parsed["received_spf"]).lower()
    auth = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        matches = re.findall(rf'\b{mechanism}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy|bestguesspass)', auth_text)
        auth[mechanism] = matches

    risks = []
    score = 0
    from_domain = parsed["from_domain"]
    reply_domain = parseaddr(parsed["reply_to"])[1].rsplit("@", 1)[-1].lower() if "@" in parseaddr(parsed["reply_to"])[1] else ""
    return_domain = parseaddr(parsed["return_path"])[1].rsplit("@", 1)[-1].lower() if "@" in parseaddr(parsed["return_path"])[1] else ""

    if not parsed["from_address"]:
        score += 15; risks.append(("medium", "Missing or malformed From address"))
    if reply_domain and from_domain and reply_domain != from_domain:
        score += 20; risks.append(("medium", f"Reply-To domain differs from From domain: {reply_domain}"))
    if return_domain and from_domain and return_domain != from_domain:
        score += 10; risks.append(("low", f"Return-Path domain differs from From domain: {return_domain}"))
    for mech, results in auth.items():
        if "fail" in results or "permerror" in results:
            score += {"spf": 20, "dkim": 20, "dmarc": 25}[mech]
            risks.append(("high", f"{mech.upper()} authentication reports failure"))
    if not parsed["authentication_results"]:
        score += 10; risks.append(("low", "No Authentication-Results header found"))
    if not parsed["dkim_signature_present"]:
        score += 10; risks.append(("low", "No DKIM-Signature header found"))
    if not parsed["received"]:
        score += 10; risks.append(("medium", "No Received trace found"))
    if any(from_domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 10; risks.append(("low", "Sender domain uses a TLD that deserves extra scrutiny"))

    score = min(score, 100)
    verdict = "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"
    return {
        "summary": parsed, "ips": ips, "public_ips": public_ips, "non_global_ips": private_ips,
        "authentication": auth, "risk_score": score, "risk_level": verdict,
        "findings": [{"severity": s, "detail": d} for s, d in risks],
        "limitations": [
            "Header-provided Authentication-Results can be forged unless added by a trusted receiving server.",
            "A header-only paste cannot cryptographically verify DKIM; provide the complete raw .eml message.",
            "SPF requires DNS and the connecting IP plus envelope identity; a header alone is not enough for authoritative SPF verification.",
            "Risk score is heuristic triage, not proof that an email is malicious or safe."
        ]
    }

def parse_eml_bytes(data: bytes) -> str:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    return msg.as_string()
