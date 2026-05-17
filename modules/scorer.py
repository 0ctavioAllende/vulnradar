"""
scorer.py — VulnRadar Risk Scorer

Dimensiones y caps (max total = 100):
    headers    → 30 pts  (era 35)
    ssl        → 25 pts  (era 30)
    cves       → 25 pts  (igual)
    subdomains → 10 pts  (igual)
    vt_intel   → 10 pts  (nuevo — output de threat_intel.vt_risk_score())
                ────────
                 100 pts

vt_intel es opcional: si no se pasa, el score se calcula igual sobre los
otros 90 pts máximos y se normaliza a 100 para mantener comparabilidad.
"""

from typing import Optional


def calculate_score(
    headers: dict,
    ssl: dict,
    cves: list,
    subdomains: list,
    vt_intel: Optional[dict] = None,
) -> dict:
    """
    Calcula el score de riesgo global de un target.

    Args:
        headers:    Output de header_analyzer. Espera "headers_missing" y "headers_weak".
        ssl:        Output de ssl_analyzer. Espera "tls_versions", "cert_valid", "days_remaining".
        cves:       Lista de CVEs. Cada item con "cvss_score" y "in_cisa_kev".
        subdomains: Lista de subdominios. Cada item con "risk" (valor "high" para penalizar).
        vt_intel:   Output de vt_risk_score() de threat_intel. Si es None, se omite la dimensión.

    Returns:
        {
            "total": int,           # 0-100
            "level": str,           # "critical" | "high" | "medium" | "low"
            "label": str,           # "Crítico" | "Alto" | "Medio" | "Bajo"
            "color": str,           # igual que level
            "breakdown": dict,      # desglose por dimensión
            "max": 100,
        }
    """
    score = 0
    breakdown = {}

    # ── 1. Headers (max 30) ──────────────────────────────────────────────────
    missing = len(headers.get("headers_missing", []))
    weak    = len(headers.get("headers_weak", []))
    header_risk = min((missing * 4) + (weak * 2), 30)
    score += header_risk
    breakdown["headers"] = {
        "risk_points": header_risk,
        "max": 30,
        "missing": missing,
        "weak": weak,
    }

    # ── 2. SSL / TLS (max 25) ───────────────────────────────────────────────
    ssl_risk = 0
    tls = ssl.get("tls_versions", {})
    if tls.get("tls_1_0"):                          ssl_risk += 15
    if tls.get("tls_1_1"):                          ssl_risk += 8
    if not ssl.get("cert_valid"):                   ssl_risk += 15
    elif ssl.get("days_remaining", 90) < 30:        ssl_risk += 7
    ssl_risk = min(ssl_risk, 25)
    score += ssl_risk
    breakdown["ssl"] = {
        "risk_points": ssl_risk,
        "max": 25,
        "tls_1_0_enabled": tls.get("tls_1_0", False),
        "tls_1_1_enabled": tls.get("tls_1_1", False),
        "cert_valid": ssl.get("cert_valid", False),
        "days_remaining": ssl.get("days_remaining"),
    }

    # ── 3. CVEs (max 25) ────────────────────────────────────────────────────
    critical_cves = [c for c in cves if (c.get("cvss_score") or 0) >= 9.0]
    high_cves     = [c for c in cves if 7.0 <= (c.get("cvss_score") or 0) < 9.0]
    kev_cves      = [c for c in cves if c.get("in_cisa_kev")]
    cve_risk = min(
        len(critical_cves) * 8 + len(high_cves) * 4 + len(kev_cves) * 5,
        25,
    )
    score += cve_risk
    breakdown["cves"] = {
        "risk_points": cve_risk,
        "max": 25,
        "critical": len(critical_cves),
        "high": len(high_cves),
        "in_cisa_kev": len(kev_cves),
    }

    # ── 4. Subdomains (max 10) ───────────────────────────────────────────────
    high_risk_subs = [s for s in subdomains if s.get("risk") == "high"]
    sub_risk = min(len(high_risk_subs) * 3, 10)
    score += sub_risk
    breakdown["subdomains"] = {
        "risk_points": sub_risk,
        "max": 10,
        "total": len(subdomains),
        "high_risk": len(high_risk_subs),
    }

    # ── 5. VirusTotal Intel (max 10, opcional) ───────────────────────────────
    if vt_intel is not None:
        # vt_risk_score() ya cap-ea en 15; lo reducimos a 10 en el scorer
        vt_risk = min(vt_intel.get("risk_points", 0), 10)
        score  += vt_risk
        breakdown["vt_intel"] = {
            "risk_points": vt_risk,
            "max": 10,
            "total_malicious": vt_intel.get("total_malicious", 0),
            "total_suspicious": vt_intel.get("total_suspicious", 0),
            "flagged_count": len(vt_intel.get("flagged", [])),
            "targets_checked": vt_intel.get("targets_checked", 0),
            "errors": len(vt_intel.get("errors", [])),
        }
    else:
        # Sin VT: normalizamos el score base (max 90) a escala de 100
        # para que los niveles de riesgo sean comparables con o sin VT
        non_vt_max = 30 + 25 + 25 + 10  # = 90
        score = round(score * 100 / non_vt_max) if score > 0 else 0
        breakdown["vt_intel"] = {
            "risk_points": 0,
            "max": 10,
            "note": "VT enrichment no disponible — score normalizado a /100",
        }

    score = min(score, 100)

    # ── Nivel de riesgo ──────────────────────────────────────────────────────
    if score >= 70:
        level, label = "critical", "Crítico"
    elif score >= 45:
        level, label = "high", "Alto"
    elif score >= 20:
        level, label = "medium", "Medio"
    else:
        level, label = "low", "Bajo"

    return {
        "total": score,
        "level": level,
        "label": label,
        "color": level,
        "breakdown": breakdown,
        "max": 100,
    }
