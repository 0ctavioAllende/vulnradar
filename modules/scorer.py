def calculate_score(headers, ssl, cves, subdomains) -> dict:
    score = 0
    breakdown = {}
    missing = len(headers.get("headers_missing", []))
    weak = len(headers.get("headers_weak", []))
    header_risk = min((missing * 4) + (weak * 2), 35)
    score += header_risk
    breakdown["headers"] = {"risk_points": header_risk, "missing": missing, "weak": weak}
    ssl_risk = 0
    tls = ssl.get("tls_versions", {})
    if tls.get("tls_1_0"): ssl_risk += 15
    if tls.get("tls_1_1"): ssl_risk += 8
    if not ssl.get("cert_valid"): ssl_risk += 15
    elif ssl.get("days_remaining", 90) < 30: ssl_risk += 7
    ssl_risk = min(ssl_risk, 30)
    score += ssl_risk
    breakdown["ssl"] = {"risk_points": ssl_risk, "tls_1_0_enabled": tls.get("tls_1_0", False), "cert_valid": ssl.get("cert_valid", False), "days_remaining": ssl.get("days_remaining")}
    cve_risk = min(len([c for c in cves if (c.get("cvss_score") or 0) >= 9.0]) * 8 + len([c for c in cves if 7 <= (c.get("cvss_score") or 0) < 9]) * 4 + len([c for c in cves if c.get("in_cisa_kev")]) * 5, 25)
    score += cve_risk
    breakdown["cves"] = {"risk_points": cve_risk, "critical": len([c for c in cves if (c.get("cvss_score") or 0) >= 9]), "high": len([c for c in cves if 7 <= (c.get("cvss_score") or 0) < 9]), "in_cisa_kev": len([c for c in cves if c.get("in_cisa_kev")])}
    sub_risk = min(len([s for s in subdomains if s.get("risk") == "high"]) * 3, 10)
    score += sub_risk
    breakdown["subdomains"] = {"risk_points": sub_risk, "total": len(subdomains), "high_risk": len([s for s in subdomains if s.get("risk") == "high"])}
    score = min(score, 100)
    if score >= 70: level, label, color = "critical", "Crítico", "critical"
    elif score >= 45: level, label, color = "high", "Alto", "high"
    elif score >= 20: level, label, color = "medium", "Medio", "medium"
    else: level, label, color = "low", "Bajo", "low"
    return {"total": score, "level": level, "label": label, "color": color, "breakdown": breakdown, "max": 100}
