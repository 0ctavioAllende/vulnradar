from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
import asyncio
import logging

logger = logging.getLogger("vulnradar.scheduler")
scheduler = AsyncIOScheduler()

async def scan_all_subscriptions():
    from modules.database import get_all_subscriptions, update_subscription_state
    from modules.notifier import detect_changes, send_alert
    from modules.header_analyzer import analyze_headers
    from modules.ssl_analyzer import analyze_ssl
    from modules.cve_correlator import correlate_cves
    from modules.subdomain_enum import enumerate_subdomains
    from modules.threat_intel import get_latam_threats
    from modules.scorer import calculate_score

    subscriptions = get_all_subscriptions()
    logger.info(f"Escaneando {len(subscriptions)} suscripciones...")

    for sub in subscriptions:
        try:
            domain = sub["domain"]
            headers_result, ssl_result, subdomains_result, threats_result = await asyncio.gather(
                analyze_headers(domain), analyze_ssl(domain),
                enumerate_subdomains(domain), get_latam_threats(domain),
            )
            cves_result = await correlate_cves(headers_result.get("detected_tech", []))
            score = calculate_score(headers_result, ssl_result, cves_result, subdomains_result)
            scan_result = {"domain": domain, "headers": headers_result, "ssl": ssl_result,
                           "cves": cves_result, "subdomains": subdomains_result,
                           "threats": threats_result, "score": score}
            changes = detect_changes(sub, scan_result)
            update_subscription_state(sub["id"], score["total"], cves_result)
            if changes["should_alert"]:
                await send_alert(sub, scan_result, changes)
            await asyncio.sleep(3)
        except Exception as e:
            logger.error(f"Error en {sub['domain']}: {e}")

def start_scheduler():
    scheduler.add_job(scan_all_subscriptions, trigger=IntervalTrigger(hours=24),
                      id="daily_scan", replace_existing=True)
    scheduler.start()
    logger.info("Scheduler iniciado")

def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown()
