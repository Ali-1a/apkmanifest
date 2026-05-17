# APKManifest

Android Manifest Security Analyzer

APKManifest is a web-based static analysis tool that scans Android APK files for security misconfigurations in the AndroidManifest.xml. Each finding is mapped to its OWASP MASVS control with a severity level and a recommended fix.

---

## Security checks

| Check | MASVS Control | Severity |
|-------|--------------|----------|
| Dangerous permissions | MASVS-PLATFORM-2 | Low / Medium / Critical |
| android:debuggable="true" | MASVS-RESILIENCE-2 | Critical |
| android:allowBackup="true" | MASVS-STORAGE-1 | Medium |
| android:usesCleartextTraffic="true" | MASVS-NETWORK-1 | Critical |
| Exported components without permission | MASVS-PLATFORM-1 | Medium |

---

## Features

- Security Score Card — instant PASS / FAIL per category
- Remediation Priority — findings sorted by severity with a one-line fix
- OWASP Mobile Top 10 Coverage — 5 / 10 categories covered via manifest analysis
- Compare two APKs — detect which issues were fixed between two versions
- PDF Report — downloadable report with all findings, MASVS IDs, and fixes
- Risk Score — weighted 0–100 score (Critical x25, Medium x10, Low x3)

---

## Installation

Requirements: Python 3.8 or higher

```bash
git clone https://github.com/Ali-1a/apkmanifest.git
cd apkmanifest
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open http://localhost:7777 in your browser.

---

## Project structure

```
apkmanifest/
├── app.py                     # Flask web server and routes
├── requirements.txt
├── analyzer/
│   ├── manifest_checker.py    # 5 security checks with MASVS mapping
│   ├── risk_scorer.py         # Weighted 0-100 scoring
│   ├── reporter.py            # PDF report generation
│   └── scanner.py             # Main orchestrator
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── results.html
│   ├── compare.html
│   ├── compare_results.html
│   ├── about.html
│   └── error.html
└── static/
    ├── css/style.css
    └── js/upload.js
```

---

## Risk levels

| Score | Level |
|-------|-------|
| 75 – 100 | Critical |
| 50 – 74 | High |
| 25 – 49 | Medium |
| 1 – 24 | Low |
| 0 | Minimal |

---

## Limitations

APKManifest analyzes AndroidManifest.xml only. It does not inspect source code, compiled bytecode, or runtime behavior. All findings should be verified manually before action is taken.

---

## Team

Ali AL-RIKABI · Wassim JABER

SMD Mobile Security Project · POLITEHNICA București · 2026

---

## License

MIT License
