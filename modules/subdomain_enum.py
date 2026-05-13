import httpx, asyncio, socket

async def enumerate_subdomains(domain: str) -> list:
    subdomains = set()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            for entry in r.json():
                for sub in entry.get("name_value", "").splitlines():
                    sub = sub.strip().lower()
                    if sub and not sub.startswith("*") and sub.endswith(domain):
                        subdomains.add(sub)
    except: pass
    tasks = [_resolve_subdomain(s) for s in list(subdomains)[:15]]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r]

async def _resolve_subdomain(subdomain: str):
    loop = asyncio.get_event_loop()
    try:
        ip = await loop.run_in_executor(None, socket.gethostbyname, subdomain)
        risk = _assess_risk(subdomain)
        return {"subdomain": subdomain, "ip": ip, "risk": risk["level"], "risk_reason": risk["reason"]}
    except socket.gaierror:
        return {"subdomain": subdomain, "ip": None, "risk": "info", "risk_reason": "No resuelve"}
    except: return None

def _assess_risk(subdomain: str) -> dict:
    name = subdomain.split(".")[0].lower()
    high_risk = ["dev","staging","test","api","admin","backend","internal","vpn","ssh","ftp"]
    medium_risk = ["beta","old","legacy","demo","preview","qa"]
    for kw in high_risk:
        if kw in name: return {"level": "high", "reason": f"Subdominio '{kw}' potencialmente expuesto"}
    for kw in medium_risk:
        if kw in name: return {"level": "medium", "reason": f"Subdominio '{kw}' — verificar exposición"}
    return {"level": "low", "reason": "Sin indicadores de riesgo"}
