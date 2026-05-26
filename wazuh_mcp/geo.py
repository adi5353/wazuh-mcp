"""GeoIP enrichment helper.

Provider priority:
  1. ipinfo.io  — HTTPS, set IPINFO_TOKEN for higher rate limits (50k/mo free tier)
  2. ip-api.com — HTTPS fallback, 45 req/min unauthenticated

Override with env var: WAZUH_GEOIP_PROVIDER=ipinfo|ip-api
"""
from __future__ import annotations

import ipaddress
import os

import httpx


async def geoip_lookup(ip: str) -> dict:
    """Return GeoIP data for a single IP address.

    Returns a dict with keys: ip, country, city, isp, asn.
    Private/loopback IPs return {"ip": ip, "geo": "private/local"}.
    On lookup failure returns {"ip": ip, "geo": "lookup_failed"}.
    """
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.is_private or parsed.is_loopback:
            return {"ip": ip, "geo": "private/local"}
    except ValueError:
        return {"ip": ip, "geo": "invalid_ip"}

    provider = os.getenv("WAZUH_GEOIP_PROVIDER", "ipinfo").lower()

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            if provider != "ip-api":
                token = os.getenv("IPINFO_TOKEN", "")
                url = f"https://ipinfo.io/{ip}/json"
                params = {"token": token} if token else {}
                r = await client.get(url, params=params)
                if r.status_code == 200:
                    data = r.json()
                    if "bogon" not in data:
                        return {
                            "ip": ip,
                            "country": data.get("country", ""),
                            "city": data.get("city", ""),
                            "isp": data.get("org", ""),
                            "asn": data.get("org", ""),
                        }

            # HTTPS fallback
            r = await client.get(
                f"https://ip-api.com/json/{ip}",
                params={"fields": "status,country,city,isp,as"},
            )
            data = r.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "country": data.get("country", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                    "asn": data.get("as", ""),
                }
    except Exception:
        pass

    return {"ip": ip, "geo": "lookup_failed"}


async def geoip_batch(ips: list[str], max_concurrent: int = 10) -> list[dict]:
    """Enrich a list of IPs concurrently, bounded by max_concurrent."""
    import asyncio

    sem = asyncio.Semaphore(max_concurrent)

    async def bounded(ip: str) -> dict:
        async with sem:
            return await geoip_lookup(ip)

    return await asyncio.gather(*[bounded(ip) for ip in ips])
