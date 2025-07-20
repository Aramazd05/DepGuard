import requests

def send_discord_alert(webhook_url, message):
    payload = {"content": message, "username": "DepGuard Bot"}
    resp = requests.post(webhook_url, json=payload)
    if resp.status_code != 204:
        print(f"Failed to send Discord alert: {resp.status_code}, {resp.text}")
