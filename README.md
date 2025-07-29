cat > README.md << 'EOF'
# DepGuard

A lightweight dependency-vulnerability scanner and reporting tool for your projects.

## Features

- **Multi-ecosystem support**: Parses `requirements.txt` (Python), `package-lock.json` (npm/Node.js) and `pom.xml` (Maven).  
- **OSV-powered**: Queries the [OSV](https://osv.dev/) database for known vulnerabilities.  
- **CVSS filtering**: Drop low-severity issues via a configurable CVSS threshold.  
- **HTML reports**: Generates timestamped HTML reports and archives previous reports in `HtmlHistory/`.  
- **SBOM output**: Produces a CycloneDX SBOM (`sbom.json`), skipping regeneration if one already exists.  
- **Discord alerts**: Posts high-severity findings to a Discord channel via webhook.  

## Table of Contents

1. [Prerequisites](#prerequisites)  
2. [Installation](#installation)  
3. [Configuration](#configuration)  
4. [Usage](#usage)  
5. [Directory Layout](#directory-layout)  
 

## Prerequisites

- **Python 3.7+**  
- A manifest file in your project root:  
  - `requirements.txt` (Python)  
  - `package-lock.json` (npm/Node.js)  
  - `pom.xml` (Maven)  

## Installation

1. Clone this repo (or copy the `depguard` folder) alongside your project 
   
  
2. Install DepGuard’s Python dependencies:
   ```bash

   pip install -r requirements.txt
   
   ```

3. Edit depguard/reports/config.txt to adjust:


Line 1: Minimum CVSS score to report (e.g. 4.0)
4.0

Line 2: Discord webhook URL, or "none" to disable alerts
https://discord.com/api/webhooks/…

CVSS threshold: only vulnerabilities ≥ this score will be included.

Discord webhook: set to none to skip notifications.


## Usage
Run DepGuard from within your project’s root (where your manifest lives):

cd /path/to/your-project
python ../depguard/main.py


What happens:

Parse your manifest (requirements.txt / package-lock.json / pom.xml).

Scan each dependency against OSV.

Print a summary in the console.

Generate or reuse (sbom.json) in HtmlAndSbom/SBOM/.

Archive old HTML reports to HtmlAndSbom/HtmlHistory/.

Write a new timestamped HTML report to HtmlAndSbom/.

Send Discord alerts for any high-severity findings (if enabled).


## Directory Layout
```bash
depguard/
├── main.py
├── scanner/
│   ├── parser.py
│   ├── scanner.py
│   └── sbom.py
├── reports/
│   ├── cli.py
│   ├── config.txt
│   ├── html_report.py
│   └── templates/
│       └── report.html
├── notifier/
│   └── discord.py
└── HtmlAndSbom/
    ├── SBOM/
    │   └── sbom.json
    ├── HtmlHistory/
    │   └── combined_report_<old-timestamp>.html
    └── combined_report_<new-timestamp>.html
```