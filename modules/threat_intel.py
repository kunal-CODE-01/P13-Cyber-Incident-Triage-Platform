import socket
import ipaddress
import requests

def analyze_threat(url, scan_ports_func):
    # Normalize URL
    url = url.strip()

    if not url.startswith("http"):
        url = "http://" + url

    try:
        domain = url.split("//")[1].split("/")[0]
        ip = socket.gethostbyname(domain)
        ip_obj = ipaddress.ip_address(ip)
    except:
        return {
            "error": "Invalid URL or domain cannot be resolved",
            "data": [],
            "summary": {
                "Open Ports": 0,
                "Closed Ports": 0,
                "Total Alerts": 0,
                "Risk": "Low"
            },
            "lat": 20,
            "lon": 78
        }

    # Security check: Block cloud metadata and reserved IPs
    if ip_obj.is_link_local or ip.startswith("169.254."):
        return {
            "error": "Cloud metadata and link-local addresses (169.254.x.x) are blocked.",
            "data": [],
            "summary": {
                "Open Ports": 0,
                "Closed Ports": 0,
                "Total Alerts": 0,
                "Risk": "Low"
            },
            "lat": 20,
            "lon": 78
        }

    # Scan ports
    result = scan_ports_func(ip)
    open_ports = len([p for p in result if str(p.get("state", "")).upper() == "OPEN"])
    closed_ports = max(0, len(result) - open_ports)

    # GEO LOCATION
    lat, lon = 20, 78
    if not (ip_obj.is_private or ip_obj.is_loopback):
        try:
            geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
            if geo.get("status") == "success":
                lat = geo.get("lat", 20)
                lon = geo.get("lon", 78)
        except Exception:
            pass

    summary = {
        "Open Ports": open_ports,
        "Closed Ports": closed_ports,
        "Total Alerts": open_ports,
        "Risk": "High" if open_ports > 5 else "Low"
    }

    return {
        "ip": ip,
        "data": result,
        "summary": summary,
        "lat": lat,
        "lon": lon
    }