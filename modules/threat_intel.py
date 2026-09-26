import socket
import requests

def analyze_threat(url, scan_ports_func):
    # Normalize URL
    url = url.strip()

    if not url.startswith("http"):
        url = "http://" + url

    try:
        domain = url.split("//")[1].split("/")[0]
        ip = socket.gethostbyname(domain)
    except:
        return {
            "error": "Invalid URL",
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
    open_ports = len(result)
    closed_ports = 100 - open_ports

    # GEO LOCATION
    lat, lon = 20, 78
    try:
        geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        if geo.get("status") == "success":
            lat = geo["lat"]
            lon = geo["lon"]
    except:
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