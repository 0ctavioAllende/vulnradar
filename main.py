from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
import asyncio
import os

from modules.header_analyzer import analyze_headers
from modules.ssl_analyzer import analyze_ssl
from modules.cve_correlator import correlate_cves
from modules.subdomain_enum import enumerate_subdomains
from modules.threat_intel import get_latam_threats, get_vt_enrichment, vt_risk_score
from modules.scorer import calculate_score
from modules.database import init_db, add_subscription, delete_subscription, get_all_subscriptions
from modules.notifier import detect_changes, send_alert

app = FastAPI(title="VulnRadar API", version="1.2.0")


def _vt_targets(domain: str, subdomains_result: list, max_subs: int = 8) -> list[str]:
    """
    Construye la lista de targets para VT enrichment:
    dominio principal + hasta max_subs subdominios.
    Soporta subdomains_result como lista de dicts o de strings.
    Cap en max_subs para respetar el rate limit del plan free (4 rpm).
    """
    targets = [domain]
    for item in subdomains_result[:max_subs]:
        if isinstance(item, dict):
            sub = item.get("subdomain") or item.get("domain") or item.get("host") or item.get("name")
        else:
            sub = str(item)
        if sub and sub not in targets:
            targets.append(sub)
    return targets

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
async def startup():
    init_db()
    try:
        from modules.scheduler import start_scheduler
        start_scheduler()
    except Exception as e:
        print(f"Scheduler no iniciado: {e}")

@app.on_event("shutdown")
async def shutdown():
    try:
        from modules.scheduler import stop_scheduler
        stop_scheduler()
    except Exception:
        pass

class ScanRequest(BaseModel):
    domain: str

class SubscribeRequest(BaseModel):
    domain: str
    email: Optional[str] = None
    ntfy_channel: Optional[str] = None
    alert_on_cve: bool = True
    alert_on_score: bool = True

class UnsubscribeRequest(BaseModel):
    domain: str
    email: str

@app.get("/")
def root():
    return {"tool": "VulnRadar", "version": "1.2.0", "status": "online"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/scan")
async def scan_domain(request: ScanRequest):
    domain = request.domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Dominio requerido")
    headers_result, ssl_result, subdomains_result, threats_result = await asyncio.gather(
        analyze_headers(domain), analyze_ssl(domain),
        enumerate_subdomains(domain), get_latam_threats(domain),
    )
    detected_tech = headers_result.get("detected_tech", [])
    vt_targets = _vt_targets(domain, subdomains_result)
    cves_result, vt_data = await asyncio.gather(
        correlate_cves(detected_tech),
        get_vt_enrichment(vt_targets),
    )
    vt_intel = vt_risk_score(vt_data)
    score = calculate_score(headers_result, ssl_result, cves_result, subdomains_result, vt_intel=vt_intel)
    return {"domain": domain, "headers": headers_result, "ssl": ssl_result,
            "cves": cves_result, "subdomains": subdomains_result,
            "threats": threats_result, "vt_enrichment": vt_data, "score": score}

@app.post("/subscribe")
async def subscribe(request: SubscribeRequest):
    domain = request.domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Dominio requerido")
    if not request.email and not request.ntfy_channel:
        raise HTTPException(status_code=400, detail="Se requiere email o canal ntfy")
    result = add_subscription(domain=domain, email=request.email,
                              ntfy_channel=request.ntfy_channel,
                              alert_on_cve=request.alert_on_cve,
                              alert_on_score=request.alert_on_score)
    if result["status"] == "created":
        try:
            headers_result, ssl_result, subdomains_result, threats_result = await asyncio.gather(
                analyze_headers(domain), analyze_ssl(domain),
                enumerate_subdomains(domain), get_latam_threats(domain),
            )
            cves_result, vt_data = await asyncio.gather(
                correlate_cves(headers_result.get("detected_tech", [])),
                get_vt_enrichment(_vt_targets(domain, subdomains_result)),
            )
            vt_intel = vt_risk_score(vt_data)
            score = calculate_score(headers_result, ssl_result, cves_result, subdomains_result, vt_intel=vt_intel)
            from modules.database import update_subscription_state
            update_subscription_state(result["id"], score["total"], cves_result)
        except Exception as e:
            print(f"Error en scan inicial: {e}")
    return {"status": result["status"],
            "message": "Suscripción activa." if result["status"] == "created" else "Ya estabas suscripto.",
            "domain": domain}

@app.delete("/subscribe")
async def unsubscribe(request: UnsubscribeRequest):
    deleted = delete_subscription(request.domain.strip().lower(), request.email)
    if not deleted:
        raise HTTPException(status_code=404, detail="Suscripción no encontrada")
    return {"status": "ok", "message": "Suscripción eliminada"}

@app.get("/subscriptions")
def list_subscriptions():
    subs = get_all_subscriptions()
    return {"total": len(subs), "subscriptions": [
        {"domain": s["domain"], "email": s["email"],
         "last_score": s["last_score"], "last_checked": s["last_checked"]}
        for s in subs
    ]}

static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/dashboard")
def dashboard():
    return FileResponse(os.path.join(static_dir, "index.html"))
