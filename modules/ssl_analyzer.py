import ssl, socket, datetime, asyncio

async def analyze_ssl(domain: str) -> dict:
    result = {"domain": domain, "cert_valid": False, "cert_expiry": None,
              "days_remaining": None, "issuer": None, "tls_versions": {},
              "weak_ciphers": [], "score": 0}
    loop = asyncio.get_event_loop()
    try:
        cert_info = await loop.run_in_executor(None, _get_cert_info, domain)
        result.update(cert_info)
        tls_versions = await loop.run_in_executor(None, _check_tls_versions, domain)
        result["tls_versions"] = tls_versions
        score = 0
        if result["cert_valid"]: score += 20
        if result.get("days_remaining", 0) > 30: score += 10
        if not tls_versions.get("tls_1_0"): score += 20
        if not tls_versions.get("tls_1_1"): score += 15
        if tls_versions.get("tls_1_3"): score += 20
        if not result["weak_ciphers"]: score += 15
        result["score"] = score
    except Exception as e:
        result["error"] = str(e)
    return result

def _get_cert_info(domain: str) -> dict:
    ctx = ssl.create_default_context()
    info = {}
    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_remaining = (not_after - datetime.datetime.utcnow()).days
                info["cert_valid"] = days_remaining > 0
                info["cert_expiry"] = not_after.strftime("%Y-%m-%d")
                info["days_remaining"] = days_remaining
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                info["issuer"] = issuer_dict.get("organizationName", "Desconocido")
                info["current_cipher"] = cipher[0] if cipher else None
                info["weak_ciphers"] = [c for c in ["RC4","DES","3DES","NULL"] if c in (cipher[0] or "").upper()]
    except Exception as e:
        info["cert_valid"] = False
        info["cert_error"] = str(e)
    return info

def _check_tls_versions(domain: str) -> dict:
    versions = {}
    checks = {
        "tls_1_2": ssl.TLSVersion.TLSv1_2,
        "tls_1_3": ssl.TLSVersion.TLSv1_3,
    }
    for label, version in checks.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    versions[label] = True
        except: versions[label] = False
    versions["tls_1_0"] = False
    versions["tls_1_1"] = False
    return versions
