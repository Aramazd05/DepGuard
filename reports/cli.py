#!/usr/bin/env python3
import sys
from scanner.parser import parse_project
from scanner.scanner import query_osv
from notifier.discord import read_config


def print_summary(data):
    print("Scan Summary:")
    for pkg in data:
        if pkg['vulns']:
            name = pkg['name']
            version = pkg.get('version', '')
            count = len(pkg['vulns'])
            risk = pkg['risk_score']
            print(f"{name}=={version}: {count} vulnerabilities, Risk Score: {risk}")


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

    # 2) Load CVSS threshold (from reports/config.txt)
    threshold, _ = read_config()
    print(f"[✔] Using CVSS threshold ≥ {threshold}")

    # 3) Scan via OSV
    print("[… ] Scanning dependencies via OSV...")
    results = []
    total_issues = 0

    for dep in deps:
        resp = query_osv(dep)
        vulns = resp.get("vulns", [])
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

    # 4) Print summary to console
    print_summary(results)


if __name__ == "__main__":
    main()
