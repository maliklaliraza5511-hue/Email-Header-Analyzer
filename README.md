# Email Header Analyzer V2 🔐

A Python-based Email Header Analyzer with a Flask web dashboard. This tool helps users inspect email headers, review authentication results, extract IP addresses, and identify suspicious email indicators.

## 🚀 Features

- Email header analysis
- Flask-based web dashboard
- SPF, DKIM, and DMARC result parsing
- Optional DNS record discovery
- Optional DKIM verification for original `.eml` files
- IP address extraction
- Suspicious email indicator detection
- JSON and HTML reports

## 🛠️ Technologies Used

- Python 3
- Flask
- HTML
- CSS
- JavaScript
- DNS lookup
- Git & GitHub

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/maliklaliraza5511-hue/Email-Header-Analyzer.git
```

### 2. Open project folder

```bash
cd Email-Header-Analyzer
```

### 3. Create virtual environment

```bash
python3 -m venv .venv
```

### 4. Activate environment

```bash
source .venv/bin/activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

## ▶️ Run the Tool

```bash
python run.py
```

Open your browser:

http://127.0.0.1:5000

## 📖 Usage

1. Start the Flask dashboard.
2. Open the local dashboard in your browser.
3. Upload an email file (`.eml` or `.txt`) or paste email headers.
4. Select optional DNS discovery if required.
5. Click Analyze Email.
6. Review the analysis results.

## ⚠️ Important Security Notes

- Header authentication results can be forged.
- DNS discovery does not perform complete SPF validation.
- DKIM verification requires the original email file.
- Risk scores are heuristic indicators, not proof of malicious activity.
- Always verify suspicious emails using trusted security tools.

## 👨‍💻 Author

**Ali Raza**

Cybersecurity Enthusiast | Python Developer

## 📄 License

This project is available for educational and authorized defensive security testing purposes.
