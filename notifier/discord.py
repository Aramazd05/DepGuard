import os
import requests

def read_config():
    """
    Reads CVSS threshold and Discord webhook URL from reports/config.txt.
    Ignores blank lines and comments (#).
    """
    default_threshold = 4.0
    default_webhook = "none"
    config_path = os.path.join(os.getcwd(), "reports", "config.txt")
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            # strip, ignore comments/empty
            lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        threshold = float(lines[0]) if len(lines) >= 1 else default_threshold
        webhook = lines[1] if len(lines) >= 2 else default_webhook
    except (FileNotFoundError, ValueError):
        threshold = default_threshold
        webhook = default_webhook
    return threshold, webhook

def send_notifications(results):
    """
    Send one or more Discord notifications if any vulnerabilities
    meet or exceed the CVSS threshold. Splits messages to stay
    under Discord’s 2,000-character limit.
    """
    threshold, webhook_url = read_config()
    if webhook_url.lower() == "none":
        return  # notifications are disabled

    # Build alert lines for each package with high-severity vulns
    alert_lines = []
    for pkg in results:
        pkg_name    = pkg.get("name", "")
        pkg_version = pkg.get("version", "")
        high_vulns  = [v for v in pkg.get("vulns", []) if v.get("score", 0) >= threshold]
        if high_vulns:
            entries = "; ".join(f"{v['id']} (CVSS {v['score']:.1f})" for v in high_vulns)
            alert_lines.append(f"• **{pkg_name}=={pkg_version}**: {entries}")

    if not alert_lines:
        return  # nothing to alert on

    header = f"🚨 High score vulnerabilities found (CVSS ≥ {threshold}):"

    # Discord has a 2000-character limit per message; we'll conservatively cap at 1900.
    max_len = 1900
    messages = []
    current = header
    for line in alert_lines:
        # +1 for the newline
        if len(current) + 1 + len(line) <= max_len:
            current += "\n" + line
        else:
            messages.append(current)
            current = header + "\n" + line
    messages.append(current)

    # Send each chunk as a separate webhook POST
    for msg in messages:
        try:
            resp = requests.post(webhook_url, json={"content": msg})
            resp.raise_for_status()
        except Exception as e:
            print(f"⚠️ Failed to send Discord notification: {e}")
