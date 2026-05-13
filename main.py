from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio

from modules.header_analyzer import analyze_headers
from modules.ssl_analyzer import analyze_ssl
from modules.cve_correlator import correlate_cves
from modules.subdomain_enum import enumerate_subdomains
from modules.threat_intel import get_latam_threats
from modules.scorer import calculate_score

app = FastAPI(
    title="VulnRadar API",
    description="Attack Surface Analyzer con Threat Intel LATAM",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    domain: str

class ScanResult(BaseModel):
    domain: str
    headers: dict
    ssl: dict
    cves: list
    subdomains: list
    threats: list
    score: dict

@app.get("/")
def root():
    return {"tool": "VulnRadar", "version": "1.0.0", "status": "online"}

@app.post("/scan", response_model=ScanResult)
async def scan_domain(request: ScanRequest):
    domain = request.domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Dominio requerido")

    # Ejecutar todos los módulos en paralelo
    headers_task    = analyze_headers(domain)
    ssl_task        = analyze_ssl(domain)
    subdomains_task = enumerate_subdomains(domain)
    threats_task    = get_latam_threats(domain)

    headers_result, ssl_result, subdomains_result, threats_result = await asyncio.gather(
        headers_task, ssl_task, subdomains_task, threats_task
    )

    # CVE correlator usa info del stack detectado en headers
    detected_tech = headers_result.get("detected_tech", [])
    cves_result = await correlate_cves(detected_tech)

    # Score agregado con todos los resultados
    score = calculate_score(headers_result, ssl_result, cves_result, subdomains_result)

    return ScanResult(
        domain=domain,
        headers=headers_result,
        ssl=ssl_result,
        cves=cves_result,
        subdomains=subdomains_result,
        threats=threats_result,
        score=score
    )

@app.get("/health")
def health():
    return {"status": "ok"}

# Servir frontend estático
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/dashboard")
def dashboard():
    return FileResponse(os.path.join(static_dir, "index.html"))
