import os
import re
import asyncio
from typing import Optional

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

# ──────────────────────────────────────────────
# LATAM Threat Intelligence DB (CERT.ar / Kaspersky LATAM)
# ──────────────────────────────────────────────

LATAM_THREAT_DB = [
    {"id": "latam-001", "title": "Campaña activa Ransomware Medusa", "severity": "critical",
     "description": "Apunta a sector financiero AR/BR. Explota TLS 1.0 y Apache desactualizado como vector inicial.",
     "source": "CERT.ar", "date": "2025-05", "sectors": ["financiero"], "countries": ["argentina", "brasil"], "cves_linked": ["CVE-2024-38475"]},
    {"id": "latam-002", "title": "Phishing kit clonando UI de banca online argentina", "severity": "high",
     "description": "Kit distribuido desde dominios .top y .xyz imitando interfaces de homebanking.",
     "source": "Kaspersky LATAM", "date": "2025-04", "sectors": ["financiero"], "countries": ["argentina"], "cves_linked": []},
    {"id": "latam-003", "title": "Explotación masiva PHP CGI — sector financiero AR", "severity": "high",
     "description": "CVE-2024-4577 explotado activamente contra servidores PHP legacy en entidades financieras.",
     "source": "CERT.ar", "date": "2024-06", "sectors": ["financiero"], "countries": ["argentina"], "cves_linked": ["CVE-2024-4577"]},
    {"id": "latam-004", "title": "Credential stuffing contra homebanking", "severity": "medium",
     "description": "Ataques automatizados usando listas de credenciales filtradas contra portales bancarios argentinos.",
     "source": "CERT.ar", "date": "2025-03", "sectors": ["financiero"], "countries": ["argentina", "chile"], "cves_linked": []},
]

async def get_latam_threats(domain: str) -> list:
    sector = _infer_sector(domain)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    relevant = [t for t in LATAM_THREAT_DB if sector in t["sectors"] or t["severity"] == "critical"]
    relevant.sort(key=lambda x: severity_order.get(x["severity"], 4))
    return [{"id": t["id"], "title": t["title"], "severity": t["severity"], "description": t["description"],
             "source": t["source"], "date": t["date"], "countries": t["countries"], "cves_linked": t["cves_linked"]}
            for t in relevant[:5]]

def _infer_sector(domain: str) -> str:
    domain_lower = domain.lower()
    financial = ["banco","bank","galicia","santander","bbva","macro","nacion","credito","financiero","bolsa","mercado"]
    for kw in financial:
        if kw in domain_lower:
            return "financiero"
    return "general"


# ──────────────────────────────────────────────
# VirusTotal Enrichment — API v3
# ──────────────────────────────────────────────

VT_API_BASE = "https://www.virustotal.com/api/v3"
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _vt_headers(api_key: Optional[str]) -> dict:
    key = api_key or os.getenv("VT_API_KEY", "")
    if not key:
        raise ValueError("VT_API_KEY no configurada. Agregá la variable de entorno o pasá api_key.")
    return {"x-apikey": key, "Accept": "application/json"}


def _parse_vt_attrs(data: dict, target: str, target_type: str) -> dict:
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values()) if stats else 0
    return {
        "target": target,
        "type": target_type,
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total_engines": total,
        "vt_score": f"{stats.get('malicious', 0)}/{total}" if total else "0/0",
        "reputation": attrs.get("reputation", 0),
        "tags": attrs.get("tags", []),
        "categories": list(attrs.get("categories", {}).values()),
        "country": attrs.get("country", ""),
        "asn": attrs.get("asn", ""),
        "as_owner": attrs.get("as_owner", ""),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "error": None,
    }


def _handle_vt_status(status_code: int, target: str) -> Optional[dict]:
    """Devuelve un dict de error si el status no es 200, o None para continuar."""
    if status_code == 404:
        return {"target": target, "found": False, "malicious": 0, "suspicious": 0,
                "vt_score": "0/0", "error": None}
    if status_code == 401:
        return {"target": target, "found": False,
                "error": "API key inválida o sin permisos"}
    if status_code == 429:
        return {"target": target, "found": False,
                "error": "Rate limit VT. Esperá 60s o usá API key premium."}
    return None


async def get_vt_domain(domain: str, api_key: Optional[str] = None) -> dict:
    """
    Consulta VirusTotal por un dominio.
    Devuelve stats de detección, reputación, tags y categorías.
    """
    if not HTTPX_AVAILABLE:
        return {"target": domain, "found": False,
                "error": "httpx no instalado. Corré: pip install httpx"}
    try:
        async with httpx.AsyncClient(timeout=12) as client:
            resp = await client.get(
                f"{VT_API_BASE}/domains/{domain}",
                headers=_vt_headers(api_key),
            )
            early = _handle_vt_status(resp.status_code, domain)
            if early:
                return early
            resp.raise_for_status()
            return _parse_vt_attrs(resp.json(), domain, "domain")
    except ValueError as e:
        return {"target": domain, "found": False, "error": str(e)}
    except Exception as e:
        return {"target": domain, "found": False, "error": f"Error: {e}"}


async def get_vt_ip(ip: str, api_key: Optional[str] = None) -> dict:
    """
    Consulta VirusTotal por una IP.
    Devuelve stats de detección, ASN, país y reputación.
    """
    if not HTTPX_AVAILABLE:
        return {"target": ip, "found": False,
                "error": "httpx no instalado. Corré: pip install httpx"}
    try:
        async with httpx.AsyncClient(timeout=12) as client:
            resp = await client.get(
                f"{VT_API_BASE}/ip_addresses/{ip}",
                headers=_vt_headers(api_key),
            )
            early = _handle_vt_status(resp.status_code, ip)
            if early:
                return early
            resp.raise_for_status()
            return _parse_vt_attrs(resp.json(), ip, "ip")
    except ValueError as e:
        return {"target": ip, "found": False, "error": str(e)}
    except Exception as e:
        return {"target": ip, "found": False, "error": f"Error: {e}"}


async def get_vt_enrichment(
    targets: list[str],
    api_key: Optional[str] = None,
    max_concurrent: int = 4,
) -> dict:
    """
    Enriquece una lista de dominios e IPs con datos de VirusTotal en paralelo.

    Args:
        targets:        Lista de dominios o IPs a consultar.
        api_key:        API key de VT. Si es None usa VT_API_KEY del entorno.
        max_concurrent: Límite de requests simultáneos (plan free: 4 RPM).

    Returns:
        Dict keyed por target::

            {
                "galicia.ar": {
                    "found": True,
                    "malicious": 0,
                    "vt_score": "0/82",
                    "tags": [],
                    ...
                },
                "dev.galicia.ar": { ... },
            }

    Ejemplo de uso en un endpoint FastAPI::

        from app.modules.threat_intel import get_vt_enrichment, vt_risk_score

        vt_data = await get_vt_enrichment(subdomain_list, api_key=settings.VT_API_KEY)
        vt_risk  = vt_risk_score(vt_data)
        score    = calculate_score(headers, ssl, cves, subdomains, vt_intel=vt_risk)
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    async def check_one(target: str) -> tuple[str, dict]:
        async with semaphore:
            fn = get_vt_ip if _IP_RE.match(target) else get_vt_domain
            return target, await fn(target, api_key)

    pairs = await asyncio.gather(*[check_one(t) for t in targets])
    return dict(pairs)


def vt_risk_score(vt_results: dict) -> dict:
    """
    Calcula los puntos de riesgo aportados por el enrichment de VT (max 15).
    Diseñado para pasarse directamente a calculate_score() como vt_intel.

    Puntaje:
        - 5 pts por cada engine que marca "malicious"
        - 2 pts por cada engine que marca "suspicious"
        - cap en 15 pts

    Returns::

        {
            "risk_points": 10,
            "total_malicious": 2,
            "total_suspicious": 0,
            "flagged": [{"target": "dev.galicia.ar", "malicious": 2, ...}],
            "targets_checked": 7,
            "errors": [],
        }
    """
    total_malicious = 0
    total_suspicious = 0
    flagged = []
    errors = []

    for target, data in vt_results.items():
        if data.get("error"):
            errors.append({"target": target, "reason": data["error"]})
            continue
        if not data.get("found"):
            continue
        mal = data.get("malicious", 0)
        sus = data.get("suspicious", 0)
        if mal > 0 or sus > 0:
            flagged.append({
                "target": target,
                "type": data.get("type", "unknown"),
                "malicious": mal,
                "suspicious": sus,
                "vt_score": data.get("vt_score", ""),
                "tags": data.get("tags", []),
                "reputation": data.get("reputation", 0),
            })
        total_malicious += mal
        total_suspicious += sus

    return {
        "risk_points": min((total_malicious * 5) + (total_suspicious * 2), 15),
        "total_malicious": total_malicious,
        "total_suspicious": total_suspicious,
        "flagged": flagged,
        "targets_checked": len(vt_results),
        "errors": errors,
    }
