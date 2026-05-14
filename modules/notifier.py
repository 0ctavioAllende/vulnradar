import httpx
import os
import json

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
NTFY_BASE = "https://ntfy.sh"

def detect_changes(subscription, scan_result):
    changes = {"should_alert": False, "new_cves": [], "score_change": 0}
    current_score = scan_result["score"]["total"]
    prev_score = subscription.get("last_score", 0)
    changes["score_change"] = current_score - prev_score
    prev_cve_ids = set(json.loads(subscription.get("last_cves", "[]")))
    new_kev_cves = [c for c in scan_result.get("cves", []) if c.get("in_cisa_kev") and c.get("id") not in prev_cve_ids]
    changes["new_cves"] = new_kev_cves
    if subscription.get("alert_on_cve") and new_kev_cves:
        changes["should_alert"] = True
    if subscription.get("alert_on_score") and changes["score_change"] >= 10:
        changes["should_alert"] = True
    return changes

async def send_alert(subscription, scan_result, changes):
    import asyncio
    domain = subscription["domain"]
    score = scan_result["score"]["total"]
    prev_score = subscription["last_score"]
    new_cves = changes.get("new_cves", [])
    score_change = changes.get("score_change", 0)
    subject = f"VulnRadar alerta para {domain}"
    if new_cves:
        subject = f"CVE critico detectado en {domain}"
    elif score_change >= 10:
        subject = f"Score de {domain} subio {score_change} puntos"
    body = f"VulnRadar detecto cambios en {domain}\nScore: {prev_score} -> {score} (+{score_change} pts)\n"
    if new_cves:
        body += "\nNuevos CVEs en CISA KEV:\n"
        for c in new_cves[:3]:
            body += f"  - {c.get('id')} CVSS {c.get('cvss_score')}\n"
    body += "\nVer reporte: https://vulnradar.onrender.com/dashboard"
    tasks = []
    if subscription.get("email") and RESEND_API_KEY:
        tasks.append(_send_email(subscription["email"], subject, body))
    if subscription.get("ntfy_channel"):
        tasks.append(_send_push(subscription["ntfy_channel"], subject, body, score))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

async def _send_email(to, subject, body):
    if not RESEND_API_KEY:
        return
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
                json={"from": "VulnRadar <onboarding@resend.dev>", "to": [to], "subject": subject, "text": body}
            )
    except Exception as e:
        print(f"Error enviando email: {e}")

async def _send_push(channel, title, message, score):
    priority = "urgent" if score >= 70 else "high" if score >= 45 else "default"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(
                f"{NTFY_BASE}/{channel}",
                headers={"Title": title, "Priority": priority, "Tags": "warning,shield",
                         "Click": "https://vulnradar.onrender.com/dashboard"},
                content=message.encode("utf-8")
            )
    except Exception as e:
        print(f"Error enviando push: {e}")
