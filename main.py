#!/usr/bin/env python3
import os
import sys


from scanner.parser import parse_project
from scanner.scanner import query_osv
from reports.html_report import generate_combined_html_report
from notifier.discord import send_notifications, read_config

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output import make_outputter, OutputFormat
from cyclonedx.schema import SchemaVersion
from reports.cli import print_summary

def main():
    # 1) Parse dependencies
    try:
        deps = parse_project()
    except FileNotFoundError as e:
        print(f"[✘] {e}")
        sys.exit(1)

    if not deps:
        print("[✘] No dependencies found to scan.")
        sys.exit(0)

    print(f"[✔] Found {len(deps)} dependencies.")

    # 2) Load CVSS threshold & webhook from config
    threshold, webhook_url = read_config()
    print(f"[✔] Using CVSS threshold ≥ {threshold}")
    if webhook_url.lower() == "none":
        print("[ℹ] Discord notifications disabled (webhook = none).")
    else:
        print(f"[✔] Discord webhook configured.")

    # 3) Scan via OSV
    print("[…] Scanning dependencies via OSV...")
    results = []
    total_issues = 0

    for dep in deps:
        resp = query_osv(dep)
        vulns = resp.get("vulns", [])
        # only keep those ≥ threshold
        filtered = [v for v in vulns if v.get("score", 0) >= threshold]
        total_issues += len(filtered)

        name = dep.get("name") or dep.get("purl")
        version = dep.get("version", "")

        results.append({
            "name": name,
            "version": version,
            "vulns": filtered,
            "risk_score": max((v.get("score", 0) for v in filtered), default=0)
        })

    print(f"[✔] Scan complete: {total_issues} vulnerabilities found (CVSS ≥ {threshold}).")
    print_summary(results)

    # 4) HTML report
    print("[…] Generating HTML report...")
    try:
        generate_combined_html_report(results)
        print("[✔] Vulnerability report generated at combined_report.html")
    except Exception as e:
        print(f"[✘] Failed to generate HTML report: {e}")

    # 5) Discord notifications
    print("[…] Sending Discord notifications (if enabled)...")
    try:
        send_notifications(results)
        print("[✔] Discord notification step complete.")
    except Exception as e:
        print(f"[✘] Failed during Discord notifications: {e}")

    # 6) Generate CycloneDX SBOM
    print("[…] Generating CycloneDX SBOM...")
    try:
        components = [
            Component(
                name=pkg.get("name"),
                version=pkg.get("version", ""),
                type=ComponentType.LIBRARY,
                purl=pkg.get("purl")
            )
            for pkg in deps
        ]

        bom = Bom(components=components)
        outputter = make_outputter(
            bom=bom,
            output_format=OutputFormat.JSON,
            schema_version=SchemaVersion.V1_4
        )
        sbom_str = outputter.output_as_string()

        sbom_file = os.getenv("SBOM_OUTPUT", "HtmlAndSbom/SBOM/cyclonedx-sbom.json")
        with open(sbom_file, "w", encoding="utf-8") as f:
            f.write(sbom_str)

        print(f"[✔] SBOM generated at {sbom_file}")
    except Exception as e:
        print(f"[✘] Failed to generate SBOM: {e}")

if __name__ == "__main__":
    main()
