import httpx

SECURITY_HEADERS = {
    "content-security-policy":    {"weight": 20, "label": "Content-Security-Policy"},
    "strict-transport-security":  {"weight": 20, "label": "HSTS"},
    "x-frame-options":            {"weight": 10, "label": "X-Frame-Options"},
    "x-content-type-options":     {"weight": 10, "label": "X-Content-Type-Options"},
    "referrer-policy":            {"weight": 10, "label": "Referrer-Policy"},
    "permissions-policy":         {"weight": 10, "label": "Permissions-Policy"},
    "cross-origin-opener-policy": {"weight": 10, "label": "COOP"},
    "x-xss-protection":           {"weight": 10, "label": "X-XSS-Protection"},
}

async def analyze_headers(domain: str) -> dict:
    url = f"https://{domain}"
    results = {
        "url": url, "status_code": None, "headers_found": {},
        "headers_missing": [], "headers_weak": [], "detected_tech": [],
        "server_info": None, "score": 0,
    }
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            response = await client.get(url)
        results["status_code"] = response.status_code
        headers = {k.lower(): v for k, v in response.headers.items()}
        server = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")
        if server:
            results["server_info"] = server
            for tech in ["Apache", "nginx", "IIS", "LiteSpeed"]:
                if tech.lower() in server.lower():
                    results["detected_tech"].append(tech.lower())
        if powered_by:
            for tech in ["PHP", "ASP.NET", "Express", "WordPress"]:
                if tech.lower() in powered_by.lower():
                    results["detected_tech"].append(tech.lower())
        if "cloudfront" in server.lower() or "x-amz-cf-id" in headers or "x-amz-cf-pop" in headers:
            results["detected_tech"].append("cloudfront")
            if "cloudfront" not in (results["server_info"] or "").lower():
                results["server_info"] = f"{results['server_info'] or ''} (CloudFront)".strip()
        if any(h in headers for h in ["x-amzn-requestid", "x-amzn-trace-id", "x-amz-request-id"]):
            if "aws" not in results["detected_tech"]:
                results["detected_tech"].append("aws")
        if any(h in headers for h in ["x-ms-request-id", "x-azure-ref", "x-msedge-ref"]):
            results["detected_tech"].append("azure")
        if "cf-ray" in headers or "cloudflare" in server.lower():
            results["detected_tech"].append("cloudflare")
        if "x-akamai-request-id" in headers or "akamai" in server.lower():
            results["detected_tech"].append("akamai")
        score = 0
        for header_key, meta in SECURITY_HEADERS.items():
            if header_key in headers:
                value = headers[header_key]
                status = _evaluate_header(header_key, value)
                results["headers_found"][meta["label"]] = {"value": value, "status": status}
                if status == "ok":
                    score += meta["weight"]
                elif status == "weak":
                    score += meta["weight"] // 2
                    results["headers_weak"].append(meta["label"])
            else:
                results["headers_missing"].append(meta["label"])
        results["score"] = score
    except httpx.ConnectError:
        results["error"] = "No se pudo conectar al dominio"
    except httpx.TimeoutException:
        results["error"] = "Timeout al conectar"
    except Exception as e:
        results["error"] = str(e)
    return results

def _evaluate_header(header: str, value: str) -> str:
    value_lower = value.lower()
    if header == "strict-transport-security":
        if "max-age" in value_lower:
            try:
                max_age = int(value_lower.split("max-age=")[1].split(";")[0].strip())
                return "ok" if max_age >= 31536000 else "weak"
            except: return "weak"
    if header == "x-frame-options":
        return "ok" if value_lower in ("deny", "sameorigin") else "weak"
    if header == "content-security-policy":
        return "weak" if "unsafe-inline" in value_lower or "unsafe-eval" in value_lower else "ok"
    if header == "x-content-type-options":
        return "ok" if value_lower == "nosniff" else "weak"
    if header == "referrer-policy":
        strong = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"}
        return "ok" if value_lower in strong else "weak"
    return "ok"
