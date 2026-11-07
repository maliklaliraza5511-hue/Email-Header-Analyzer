import argparse, json
from pathlib import Path
from .core import analyze
from .dns_checks import domain_checks, verify_dkim
from .report import save_json, save_html

def main():
    p = argparse.ArgumentParser(description="Email Header Analyzer PRO — authorized email forensics")
    p.add_argument("file", help="Raw .eml file or text file containing headers")
    p.add_argument("--dns", action="store_true", help="Discover sender-domain SPF and DMARC TXT records")
    p.add_argument("--dkim-verify", action="store_true", help="Attempt DKIM verification (requires complete .eml)")
    p.add_argument("--json", default="report.json", help="JSON report output path")
    p.add_argument("--html", default="report.html", help="HTML report output path")
    args = p.parse_args()
    path = Path(args.file)
    raw_bytes = path.read_bytes()
    raw = raw_bytes.decode("utf-8", "replace")
    result = analyze(raw)
    if args.dns:
        result["dns_checks"] = domain_checks(result["summary"]["from_domain"])
    if args.dkim_verify:
        result["dkim_verification"] = verify_dkim(raw_bytes)
    save_json(result, args.json); save_html(result, args.html)
    print(json.dumps({k: result[k] for k in ("risk_score", "risk_level", "findings", "authentication", "ips")}, indent=2))
    print(f"\nReports saved: {args.json}, {args.html}")

if __name__ == "__main__":
    main()
