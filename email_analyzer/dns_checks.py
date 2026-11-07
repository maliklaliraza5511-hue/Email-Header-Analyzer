from __future__ import annotations
import re

def lookup_txt(name: str) -> list[str]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(name, "TXT", lifetime=4)
        return [b"".join(r.strings).decode("utf-8", "replace") for r in answers]
    except Exception:
        return []

def domain_checks(domain: str) -> dict:
    if not domain:
        return {"error": "No sender domain available"}
    spf = [x for x in lookup_txt(domain) if x.lower().startswith("v=spf1")]
    dmarc = [x for x in lookup_txt("_dmarc." + domain) if x.lower().startswith("v=dmarc1")]
    return {
        "domain": domain,
        "spf_records": spf,
        "dmarc_records": dmarc,
        "notes": [
            "DNS record discovery is not a full SPF evaluation.",
            "DMARC alignment and policy enforcement require evaluating the authenticated SPF/DKIM identities.",
            "DKIM public-key lookup requires the selector from DKIM-Signature (s=) and signing domain (d=)."
        ]
    }

def verify_dkim(raw_eml: bytes) -> dict:
    try:
        import dkim
        valid = dkim.verify(raw_eml)
        return {"available": True, "verified": bool(valid), "detail": "DKIM cryptographic verification attempted on complete raw message"}
    except ImportError:
        return {"available": False, "verified": None, "detail": "Install dkimpy to enable DKIM verification"}
    except Exception as exc:
        return {"available": True, "verified": False, "detail": f"DKIM verification error: {type(exc).__name__}"}
