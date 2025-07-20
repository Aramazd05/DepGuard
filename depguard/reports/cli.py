def print_summary(data):
    print("Scan Summary:")
    for pkg in data:
        if pkg['vulns']:
            print(f"{pkg['name']}=={pkg.get('version','')}: {len(pkg['vulns'])} vulnerabilities, Risk Score: {pkg['risk_score']}")
