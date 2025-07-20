# main.py

import os
from scanner.parser import parse_project
from scanner.scanner import query_osv
from reports.html_report import generate_combined_html_report
from notifier.discord import send_discord_alert

def main():
    # 1) Parse your project’s dependencies (supports Python, npm, Maven)
    deps = parse_project()

    # 2) Get threshold from env (default 4.0 → MEDIUM+)
    threshold = float(os.getenv("MIN_CVSS", "4.0"))

    all_results = []
    alerts = []

    # 3) Scan each dependency via OSV.dev and filter by CVSS3 ≥ threshold
    for dep in deps:
        name = dep.get("name") or dep.get("purl")
        version = dep.get("version", "")
        print(f"Scanning {name} {version}…")
        res = query_osv(dep)

        # Keep only vulns with score ≥ threshold
        qualifying = [v for v in res.get("vulns", []) if (v.get("score") or 0) >= threshold]
        if qualifying:
            alerts.append((name, qualifying))

        # Compute package risk score = highest CVSS3 score (or 0)
        risk = max((v.get("score") or 0) for v in res.get("vulns", [])) if res.get("vulns") else 0

        all_results.append({
            "name":       name,
            "version":    version,
            "vulns":      res.get("vulns", []),
            "risk_score": risk
        })

    # 4) Write a combined HTML report
    generate_combined_html_report(all_results, output_file="combined_report.html")
    print("Saved combined_report.html")

    # 5) If any qualifying vulns, send a Discord alert
    webhook_url = os.getenv("DISCORD_WEBHOOK", "").strip()
    if webhook_url and alerts:
        lines = ["🚨 **DepGuard Alert:** CVSS v3 ≥ 4.0 vulnerabilities detected!"]
        for pkg_name, vuln_list in alerts:
            entries = "; ".join(f"{v['id']}({v['score']})" for v in vuln_list)
            lines.append(f"- **{pkg_name}**: {entries}")
        message = "\n".join(lines)
        send_discord_alert(webhook_url, message)
    elif not webhook_url:
        print("No DISCORD_WEBHOOK set; skipping Discord alert.")

if __name__ == "__main__":
    main()
