"""
IP geolocation and CIDR range lookup.
Fetches IP ranges for selected country/province/city from online sources.
"""

import json
import threading
from urllib.request import Request, urlopen
from urllib.error import URLError
import ssl
import re


# ---------------------------------------------------------------------------
# Online IP range sources
# ---------------------------------------------------------------------------

# Major ISP IP allocation data (free, public)
IP_RANGE_SOURCES = {
    "apnic": "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest",
    "ripe": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
    "lacnic": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest",
    "arin": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest",
}

# Geo API for IP-to-location lookup
GEO_API_ENDPOINTS = [
    "http://ip-api.com/json/{ip}",
    "https://api.ip.sb/geoip/{ip}",
]


# ---------------------------------------------------------------------------
# Country codes mapping (subset of major countries)
# ---------------------------------------------------------------------------

COUNTRY_CODES = {
    "China": "CN",
    "United States": "US",
    "Japan": "JP",
    "South Korea": "KR",
    "Germany": "DE",
    "United Kingdom": "GB",
    "France": "FR",
    "Russia": "RU",
    "India": "IN",
    "Brazil": "BR",
    "Canada": "CA",
    "Australia": "AU",
    "Singapore": "SG",
    "Taiwan": "TW",
    "Hong Kong": "HK",
    "Vietnam": "VN",
    "Thailand": "TH",
    "Indonesia": "ID",
    "Malaysia": "MY",
    "Philippines": "PH",
}

# Per-country IP prefixes (pre-cached common ranges, updated on fetch)
_COUNTRY_IPCACHE = {}
_IPCACHE_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# IP Range Fetcher
# ---------------------------------------------------------------------------

def _fetch_url(url, timeout=15):
    """Fetch URL with SSL verification disabled (public data)."""
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        req = Request(url, headers={"User-Agent": "IPRangeScanner/1.0"})
        resp = urlopen(req, timeout=timeout, context=ssl_ctx)
        return resp.read().decode("utf-8", errors="replace")
    except (URLError, OSError) as e:
        return None


def _parse_apnic_data(text, country_code):
    """Parse APNIC delegated stats and extract IPv4 CIDRs for a country."""
    cidrs = []
    if not text:
        return cidrs
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.strip().split("|")
        if len(parts) < 5:
            continue
        # Format: registry|cc|type|start|value|date|status
        registry, cc, rtype, start, value = parts[0], parts[1], parts[2], parts[3], parts[4]
        if rtype == "ipv4" and cc.upper() == country_code.upper():
            try:
                prefix_len = 32 - (int(value).bit_length() - 1)
                if 2**prefix_len != int(value):
                    prefix_len = 32 - (int(value).bit_length() - 1)
                cidrs.append(f"{start}/{prefix_len}")
            except (ValueError, IndexError):
                continue
    return cidrs


def fetch_country_cidrs(country_name, on_progress=None):
    """
    Fetch IPv4 CIDR ranges for a given country from online databases.
    Returns list of CIDR strings like ['1.0.1.0/24', '1.0.2.0/23', ...]
    """
    country_code = COUNTRY_CODES.get(country_name, country_name.upper()[:2])

    with _IPCACHE_LOCK:
        if country_code in _COUNTRY_IPCACHE:
            return _COUNTRY_IPCACHE[country_code]

    all_cidrs = []
    sources = list(IP_RANGE_SOURCES.items())

    for i, (source_name, url) in enumerate(sources):
        if on_progress:
            on_progress(i + 1, len(sources), f"Fetching {source_name}...")

        text = _fetch_url(url, timeout=20)
        if text:
            cidrs = _parse_apnic_data(text, country_code)
            all_cidrs.extend(cidrs)

    # Deduplicate and sort
    all_cidrs = sorted(set(all_cidrs))

    with _IPCACHE_LOCK:
        _COUNTRY_IPCACHE[country_code] = all_cidrs

    return all_cidrs


# ---------------------------------------------------------------------------
# CIDR → IP Range conversion
# ---------------------------------------------------------------------------

def cidr_to_range(cidr):
    """Convert a CIDR like '192.168.1.0/24' to (start_ip, end_ip)."""
    import ipaddress
    net = ipaddress.IPv4Network(cidr, strict=False)
    start = str(net.network_address)
    end = str(net.broadcast_address)
    return start, end


def get_aggregated_ranges(cidrs, max_ranges=20):
    """
    Aggregate CIDRs into larger supernets for efficient scanning.
    Limits output to max_ranges entries (merge adjacent CIDRs).
    Returns list of (start_ip, end_ip) tuples.
    """
    import ipaddress

    if not cidrs:
        return []

    # Sort by network address
    networks = sorted(
        [ipaddress.IPv4Network(c, strict=False) for c in cidrs],
        key=lambda n: int(n.network_address),
    )

    # Simple aggregation: merge contiguous /24s into /16s where possible
    merged = []
    for net in networks:
        if not merged:
            merged.append(net)
            continue
        last = merged[-1]
        last_end = int(last.broadcast_address)
        this_start = int(net.network_address)
        if this_start <= last_end + 1:
            try:
                combined_range = ipaddress.IPv4Network(
                    f"{last.network_address}/"
                    f"{min(last.prefixlen, net.prefixlen) - 1}",
                    strict=False,
                )
                if int(combined_range.broadcast_address) >= int(net.broadcast_address):
                    merged[-1] = combined_range
                    continue
            except (ValueError, ipaddress.AddressValueError):
                pass
        merged.append(net)

    # Truncate to max_ranges
    if len(merged) > max_ranges:
        # Keep largest ranges
        merged.sort(key=lambda n: n.num_addresses, reverse=True)
        merged = merged[:max_ranges]

    return [(str(n.network_address), str(n.broadcast_address)) for n in merged]


# ---------------------------------------------------------------------------
# IP location lookup
# ---------------------------------------------------------------------------

def lookup_ip(ip):
    """Look up geolocation for a single IP. Returns dict or None."""
    for endpoint in GEO_API_ENDPOINTS:
        url = endpoint.format(ip=ip)
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        try:
            req = Request(url, headers={"User-Agent": "IPScanner/1.0"})
            resp = urlopen(req, timeout=5, context=ssl_ctx)
            data = json.loads(resp.read().decode("utf-8"))
            if "country" in data or "countryCode" in data:
                return {
                    "ip": ip,
                    "country": data.get("country", data.get("countryCode", "?")),
                    "region": data.get("regionName", data.get("region", "?")),
                    "city": data.get("city", "?"),
                    "isp": data.get("isp", data.get("org", "?")),
                }
        except (URLError, json.JSONDecodeError, OSError):
            continue
    return {"ip": ip, "country": "?", "region": "?", "city": "?", "isp": "?"}


# ---------------------------------------------------------------------------
# China-specific IP ranges (pre-cached for speed)
# ---------------------------------------------------------------------------

CHINA_MAJOR_ISP_RANGES = [
    ("1.0.1.0", "1.0.3.255"),      # China Telecom
    ("1.0.8.0", "1.0.15.255"),     # China Telecom
    ("1.0.32.0", "1.0.63.255"),    # China Telecom
    ("1.1.0.0", "1.1.7.255"),      # China Telecom
    ("1.1.8.0", "1.1.63.255"),     # China Telecom
    ("1.2.0.0", "1.2.2.255"),      # China Telecom
    ("1.2.4.0", "1.2.127.255"),    # China Telecom / CNNIC
    ("1.3.0.0", "1.3.255.255"),    # China Telecom
    ("1.4.1.0", "1.4.127.255"),    # China Telecom
    ("1.8.0.0", "1.8.255.255"),    # China Telecom
    ("1.10.8.0", "1.10.11.255"),   # China Telecom
    ("1.10.128.0", "1.10.255.255"), # China Telecom
    ("1.12.0.0", "1.15.255.255"),  # China Telecom
    ("1.24.0.0", "1.31.255.255"),  # China Unicom
    ("14.0.0.0", "14.0.15.255"),   # China Telecom
    ("14.1.0.0", "14.1.31.255"),   # China Telecom
    ("14.16.0.0", "14.23.255.255"), # China Telecom
    ("14.24.0.0", "14.24.255.255"), # China Mobile
]

PROVINCE_RANGES_CN = {
    "Beijing": [
        ("1.202.0.0", "1.203.255.255"),
        ("101.38.0.0", "101.39.255.255"),
        ("111.192.0.0", "111.207.255.255"),
        ("114.240.0.0", "114.255.255.255"),
        ("123.112.0.0", "123.127.255.255"),
    ],
    "Shanghai": [
        ("101.80.0.0", "101.95.255.255"),
        ("114.80.0.0", "114.95.255.255"),
        ("116.226.0.0", "116.239.255.255"),
        ("180.152.0.0", "180.159.255.255"),
        ("218.78.0.0", "218.83.255.255"),
    ],
    "Guangdong": [
        ("14.112.0.0", "14.127.255.255"),
        ("27.36.0.0", "27.39.255.255"),
        ("59.32.0.0", "59.43.255.255"),
        ("113.64.0.0", "113.111.255.255"),
        ("116.16.0.0", "116.31.255.255"),
        ("119.128.0.0", "119.143.255.255"),
        ("121.8.0.0", "121.15.255.255"),
        ("183.0.0.0", "183.63.255.255"),
    ],
    "Zhejiang": [
        ("60.160.0.0", "60.191.255.255"),
        ("115.192.0.0", "115.239.255.255"),
        ("122.224.0.0", "122.239.255.255"),
        ("124.160.0.0", "124.175.255.255"),
        ("125.104.0.0", "125.127.255.255"),
    ],
    "Jiangsu": [
        ("49.64.0.0", "49.95.255.255"),
        ("58.208.0.0", "58.223.255.255"),
        ("114.220.0.0", "114.239.255.255"),
        ("117.80.0.0", "117.95.255.255"),
        ("121.224.0.0", "121.239.255.255"),
        ("180.96.0.0", "180.111.255.255"),
        ("221.224.0.0", "221.231.255.255"),
    ],
    "Sichuan": [
        ("61.128.0.0", "61.143.255.255"),
        ("110.184.0.0", "110.191.255.255"),
        ("118.112.0.0", "118.127.255.255"),
        ("119.0.0.0", "119.7.255.255"),
        ("171.208.0.0", "171.223.255.255"),
    ],
    "Hubei": [
        ("27.16.0.0", "27.31.255.255"),
        ("58.48.0.0", "58.55.255.255"),
        ("113.56.0.0", "113.63.255.255"),
        ("119.96.0.0", "119.103.255.255"),
        ("171.112.0.0", "171.127.255.255"),
    ],
    "Fujian": [
        ("59.56.0.0", "59.63.255.255"),
        ("110.80.0.0", "110.95.255.255"),
        ("117.24.0.0", "117.31.255.255"),
        ("121.204.0.0", "121.207.255.255"),
        ("218.85.0.0", "218.87.255.255"),
        ("222.76.0.0", "222.79.255.255"),
    ],
    "Shandong": [
        ("27.192.0.0", "27.223.255.255"),
        ("58.56.0.0", "58.59.255.255"),
        ("60.208.0.0", "60.223.255.255"),
        ("119.176.0.0", "119.191.255.255"),
        ("123.128.0.0", "123.135.255.255"),
        ("144.0.0.0", "144.15.255.255"),
    ],
    "Henan": [
        ("61.52.0.0", "61.55.255.255"),
        ("115.48.0.0", "115.63.255.255"),
        ("123.0.0.0", "123.15.255.255"),
        ("125.40.0.0", "125.47.255.255"),
        ("222.136.0.0", "222.143.255.255"),
    ],
    "Liaoning": [
        ("59.44.0.0", "59.47.255.255"),
        ("60.16.0.0", "60.23.255.255"),
        ("113.224.0.0", "113.239.255.255"),
        ("123.184.0.0", "123.191.255.255"),
        ("175.160.0.0", "175.175.255.255"),
    ],
    "Tianjin": [
        ("60.24.0.0", "60.31.255.255"),
        ("111.160.0.0", "111.167.255.255"),
        ("117.8.0.0", "117.15.255.255"),
        ("218.68.0.0", "218.69.255.255"),
    ],
}

# Map provinces to major cities (first city is default)
PROVINCE_CITIES = {
    "Beijing": ["Beijing"],
    "Shanghai": ["Shanghai"],
    "Guangdong": ["Guangzhou", "Shenzhen", "Dongguan", "Foshan", "Zhuhai"],
    "Zhejiang": ["Hangzhou", "Ningbo", "Wenzhou", "Jiaxing", "Shaoxing"],
    "Jiangsu": ["Nanjing", "Suzhou", "Wuxi", "Changzhou", "Nantong"],
    "Sichuan": ["Chengdu", "Mianyang", "Deyang", "Nanchong"],
    "Hubei": ["Wuhan", "Yichang", "Xiangyang"],
    "Fujian": ["Fuzhou", "Xiamen", "Quanzhou", "Zhangzhou"],
    "Shandong": ["Jinan", "Qingdao", "Yantai", "Weifang"],
    "Henan": ["Zhengzhou", "Luoyang", "Kaifeng"],
    "Liaoning": ["Shenyang", "Dalian"],
    "Tianjin": ["Tianjin"],
}

# More granular: city-level IP ranges (sample - full ranges are large)
CITY_RANGES_CN = {
    "Beijing": PROVINCE_RANGES_CN.get("Beijing", []),
    "Shanghai": PROVINCE_RANGES_CN.get("Shanghai", []),
    "Guangzhou": [
        ("113.64.0.0", "113.71.255.255"),
        ("116.20.0.0", "116.23.255.255"),
        ("119.128.0.0", "119.131.255.255"),
        ("121.8.0.0", "121.9.255.255"),
        ("183.32.0.0", "183.39.255.255"),
        ("218.19.0.0", "218.21.255.255"),
    ],
    "Shenzhen": [
        ("113.72.0.0", "113.91.255.255"),
        ("116.24.0.0", "116.25.255.255"),
        ("119.136.0.0", "119.137.255.255"),
        ("121.12.0.0", "121.15.255.255"),
        ("183.12.0.0", "183.19.255.255"),
        ("220.230.0.0", "220.231.255.255"),
    ],
    "Hangzhou": [
        ("60.176.0.0", "60.191.255.255"),
        ("115.192.0.0", "115.207.255.255"),
        ("122.224.0.0", "122.225.255.255"),
        ("124.168.0.0", "124.175.255.255"),
        ("125.104.0.0", "125.105.255.255"),
    ],
    "Nanjing": [
        ("49.64.0.0", "49.79.255.255"),
        ("58.208.0.0", "58.209.255.255"),
        ("114.220.0.0", "114.223.255.255"),
        ("117.80.0.0", "117.81.255.255"),
        ("121.224.0.0", "121.225.255.255"),
        ("180.100.0.0", "180.103.255.255"),
        ("221.226.0.0", "221.227.255.255"),
    ],
    "Chengdu": [
        ("61.128.0.0", "61.129.255.255"),
        ("110.184.0.0", "110.185.255.255"),
        ("118.112.0.0", "118.113.255.255"),
        ("119.0.0.0", "119.1.255.255"),
        ("171.210.0.0", "171.211.255.255"),
    ],
    "Wuhan": [
        ("27.16.0.0", "27.19.255.255"),
        ("58.48.0.0", "58.49.255.255"),
        ("113.56.0.0", "113.57.255.255"),
        ("119.100.0.0", "119.101.255.255"),
        ("171.112.0.0", "171.113.255.255"),
    ],
}


def get_province_ranges(province):
    """Get IP ranges for a Chinese province."""
    return PROVINCE_RANGES_CN.get(province, [])


def get_city_ranges(city):
    """Get IP ranges for a Chinese city."""
    return CITY_RANGES_CN.get(city, [])


def get_china_ranges():
    """Get aggregated China-wide IP ranges."""
    result = []
    for ranges in PROVINCE_RANGES_CN.values():
        result.extend(ranges)
    return sorted(set(result))