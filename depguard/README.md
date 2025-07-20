# DepGuard v2

## Features
- CVSS 4.0–only vulnerability scanning via OSV.dev
- Detailed CVSS v4 metric breakdown
- Severity filtering (via MIN_CVSS environment variable)
- Risk scoring per package
- Combined HTML report
- Discord alerts via webhook (via DISCORD_WEBHOOK environment variable)
- Support for Python (requirements.txt), npm (package-lock.json), and Maven (pom.xml)

## Setup
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
