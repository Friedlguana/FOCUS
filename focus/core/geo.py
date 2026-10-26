"""IP geolocation with provider fallback and an on-disk Leaflet map."""

from __future__ import annotations

import html
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import requests

from .net import Connection, established_connections
from .paths import MAP_FILE

USER_AGENT = "FOCUS/2.0 (network security framework)"
TIMEOUT = (3.05, 8)

_CACHE: dict[str, tuple[float, "GeoResult"]] = {}
_CACHE_TTL = 60 * 60


@dataclass
class GeoResult:
    ip: str
    city: str
    region: str
    country: str
    country_code: str
    isp: str
    asn: str
    latitude: float | None
    longitude: float | None
    source: str

    @property
    def location(self) -> str:
        parts = [part for part in (self.city, self.region, self.country) if part]
        return ", ".join(dict.fromkeys(parts)) or "Unknown"


def _text(value: object, fallback: str = "Unknown") -> str:
    if value is None:
        return fallback
    text = str(value).strip()
    return text or fallback


def _from_ipwho(ip: str, data: dict) -> GeoResult | None:
    if not data.get("success", False):
        return None
    connection = data.get("connection") or {}
    asn = connection.get("asn")
    return GeoResult(
        ip=ip,
        city=_text(data.get("city")),
        region=_text(data.get("region")),
        country=_text(data.get("country")),
        country_code=_text(data.get("country_code"), ""),
        isp=_text(connection.get("isp") or connection.get("org")),
        asn=f"AS{asn}" if asn else "—",
        latitude=data.get("latitude"),
        longitude=data.get("longitude"),
        source="ipwho.is",
    )


def _from_ipapi(ip: str, data: dict) -> GeoResult | None:
    if data.get("error"):
        return None
    return GeoResult(
        ip=ip,
        city=_text(data.get("city")),
        region=_text(data.get("region")),
        country=_text(data.get("country_name")),
        country_code=_text(data.get("country_code"), ""),
        isp=_text(data.get("org")),
        asn=_text(data.get("asn"), "—"),
        latitude=data.get("latitude"),
        longitude=data.get("longitude"),
        source="ipapi.co",
    )


def _from_ipapi_com(ip: str, data: dict) -> GeoResult | None:
    if data.get("status") != "success":
        return None
    return GeoResult(
        ip=ip,
        city=_text(data.get("city")),
        region=_text(data.get("regionName")),
        country=_text(data.get("country")),
        country_code=_text(data.get("countryCode"), ""),
        isp=_text(data.get("isp")),
        asn=_text(data.get("as"), "—"),
        latitude=data.get("lat"),
        longitude=data.get("lon"),
        source="ip-api.com",
    )


PROVIDERS = (
    ("https://ipwho.is/{ip}", _from_ipwho),
    ("https://ipapi.co/{ip}/json/", _from_ipapi),
    ("https://ip-api.com/json/{ip}", _from_ipapi_com),
)


def lookup(ip: str, *, timeout: float = 8.0, use_cache: bool = True) -> GeoResult | None:
    """Resolve an IP, trying each provider until one returns coordinates."""
    cached = _CACHE.get(ip)
    if use_cache and cached and time.time() - cached[0] < _CACHE_TTL:
        return cached[1]

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    for template, parse in PROVIDERS:
        url = template.format(ip=ip)
        try:
            response = session.get(url, timeout=(3.05, timeout))
        except requests.RequestException:
            continue
        if response.status_code != 200:
            continue
        try:
            result = parse(ip, response.json())
        except (ValueError, TypeError):
            continue
        if result and result.latitude is not None and result.longitude is not None:
            _CACHE[ip] = (time.time(), result)
            return result

    return None


def lookup_many(addresses: list[str], *, timeout: float = 5.0, workers: int = 4) -> dict[str, GeoResult | None]:
    """Resolve several addresses concurrently, preserving all keys.

    A failed lookup is stored as ``None`` so the UI can distinguish "finished
    and unavailable" from "still resolving".
    """
    unique = list(dict.fromkeys(address for address in addresses if address))
    if not unique:
        return {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(unique)))) as pool:
        results = list(pool.map(lambda address: lookup(address, timeout=timeout), unique))
    return dict(zip(unique, results))


def external_targets(limit: int = 8) -> list[tuple[str, list[Connection]]]:
    """The most-connected public IPs, private and loopback addresses removed."""
    grouped: dict[str, list[Connection]] = {}
    for conn in established_connections():
        if conn.private:
            continue
        grouped.setdefault(conn.remote_ip, []).append(conn)

    ordered = sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0]))
    return ordered[: max(1, limit)]


def write_map(results: list[GeoResult], path: Path = MAP_FILE) -> Path:
    """Render all located endpoints into a single dark Leaflet map."""
    points = [
        {
            "ip": item.ip,
            "label": item.location,
            "isp": item.isp,
            "asn": item.asn,
            "lat": item.latitude,
            "lon": item.longitude,
            "source": item.source,
        }
        for item in results
        if item.latitude is not None and item.longitude is not None
    ]

    payload = json.dumps(points, ensure_ascii=False).replace("</", "<\\/")
    title = html.escape("FOCUS · endpoint locations")
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: #1a1b26; color: #c0caf5;
          font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  header {{ padding: 18px 24px; border-bottom: 1px solid #2f3549; display: flex;
            align-items: baseline; gap: 16px; }}
  h1 {{ margin: 0; font-size: 16px; letter-spacing: .18em; font-weight: 600; }}
  header span {{ color: #565f89; font-size: 12px; }}
  #map {{ height: calc(100vh - 58px); width: 100%; background: #1a1b26; }}
  .leaflet-popup-content-wrapper, .leaflet-popup-tip {{
    background: #1f2335; color: #c0caf5; border: 1px solid #2f3549; box-shadow: none; }}
  .leaflet-popup-content {{ margin: 12px 14px; font-family: inherit; }}
  .leaflet-popup-content b {{ color: #7aa2f7; }}
  .leaflet-container a.leaflet-popup-close-button {{ color: #565f89; }}
  .leaflet-control-attribution {{ background: #1f2335 !important; color: #565f89 !important; }}
  .leaflet-control-attribution a {{ color: #7aa2f7 !important; }}
</style>
</head>
<body>
<header><h1>FOCUS</h1><span>endpoint locations · {len(points)} host(s) · map tiles load online</span></header>
<div id="map"></div>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
  const points = {payload};
  function esc(value) {{
    return String(value).replace(/[&<>"']/g, function (ch) {{
      return {{'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}}[ch];
    }});
  }}
  const map = L.map('map', {{ zoomControl: true, attributionControl: true }})
                 .setView([20, 0], 2);
  L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
    maxZoom: 19,
    attribution: '&copy; OpenStreetMap contributors &copy; CARTO'
  }}).addTo(map);

  const bounds = [];
  for (const point of points) {{
    const marker = L.circleMarker([point.lat, point.lon], {{
      radius: 6, color: '#7aa2f7', weight: 2, fillColor: '#7aa2f7', fillOpacity: 0.25
    }}).addTo(map);
    marker.bindPopup(
      '<b>' + esc(point.ip) + '</b><br>' + esc(point.label) +
      '<br>' + esc(point.isp) + ' · ' + esc(point.asn) +
      '<br><span style="color:#565f89">via ' + esc(point.source) + '</span>'
    );
    bounds.push([point.lat, point.lon]);
  }}
  if (bounds.length === 1) map.setView(bounds[0], 9);
  else if (bounds.length > 1) map.fitBounds(bounds, {{ padding: [48, 48] }});
</script>
</body>
</html>
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")
    return path
