# Email Header Analyzer PRO V2 — Local Dashboard

## Install on Kali
```bash
cd email_header_analyzer_pro_v2
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Start dashboard
```bash
python run.py
```
Open `http://127.0.0.1:5000` in your browser. The app binds to localhost only.

## Use
- Upload a raw `.eml` or `.txt` file, or paste headers.
- Optional DNS discovery queries sender-domain SPF and DMARC TXT records.
- Optional DKIM cryptographic verification is attempted only for uploaded `.eml` files.
- Export the analysis JSON or print the report.

## Safety and accuracy
This is a defensive triage aid. Treat untrusted Authentication-Results as untrusted until the receiving server boundary is established. DNS discovery is not full SPF/DMARC validation. DKIM verification requires the complete original message and can fail for reasons other than maliciousness. Risk score is heuristic, not a verdict. Upload only email you are authorized to inspect.
