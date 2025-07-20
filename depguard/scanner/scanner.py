import requests
from cvss import CVSS3

OSV_API = "https://api.osv.dev/v1/query"

def _score_to_severity(score):
    """Convert numeric CVSS3 base score into a text severity."""
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "NONE"

def query_osv(dep):
    # 1) Build the payload
    if "purl" in dep:
        payload = {"package": {"purl": dep["purl"]}}
    else:
        payload = {
            "package": {
                "name": dep["name"],
                "ecosystem": dep["ecosystem"]
            },
            "version": dep["version"]
        }

    # 2) Fetch from OSV
    resp = requests.post(OSV_API, json=payload)
    if resp.status_code != 200:
        return {"vulns": []}
    data = resp.json()

    # 3) Filter & parse CVSS v3
    vulns = []
    for vuln in data.get("vulns", []):
        for sev in vuln.get("severity", []):
            if sev.get("type") != "CVSS_V3":
                continue

            vector = sev["score"]
            try:
        # 1️⃣ Parse with CVSS3 to get the numeric score
                    cv = CVSS3(vector)
                    base_score = cv.base_score

        # 2️⃣ Derive a text severity (since cv.severity doesn't exist)
                    if   base_score >= 9.0: severity = "CRITICAL"
                    elif base_score >= 7.0: severity = "HIGH"
                    elif base_score >= 4.0: severity = "MEDIUM"
                    elif base_score >= 0.1: severity = "LOW"
                    else:                   severity = "NONE"

        # 3️⃣ Manually split out each Base metric from the vector string
        #    Vector format per CVSS v3 spec: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N' :contentReference[oaicite:0]{index=0}
                    metrics = {
                        part.split(":",1)[0]: part.split(":",1)[1]
                        for part in vector.split("/", 1)[1].split("/")
                    }

            except Exception as e:
                    print(f"[CVSS3 parse error] {vuln.get('id')} vector={vector!r}: {e}")
                    continue


            vulns.append({
                "id":       vuln.get("id"),
                "vector":   vector,
                "score":    base_score,
                "severity": severity,
                "metrics":  metrics,
                "details":  vuln.get("details", "")
            })

    return {"vulns": vulns}
