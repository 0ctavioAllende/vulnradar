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
        if kw in domain_lower: return "financiero"
    return "general"
