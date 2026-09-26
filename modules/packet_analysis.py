import re

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, Raw
except Exception:
    rdpcap = IP = TCP = UDP = ICMP = ARP = Raw = None


def analyze_packet(data):
    data = str(data)
    lower = data.lower()
    results = []

    # Enhanced pattern detection
    if re.search(r"(\b(union\s+(all\s+)?select|select\s+.+\s+from|insert\s+into|drop\s+table)\b|or\s+['\"]?1['\"]?\s*=\s*['\"]?1)", lower):
        results.append("⚠ SQL Injection Detected")
    elif "select " in lower or "or 1=1" in lower:
        results.append("⚠ SQL Injection Detected")

    if re.search(r"(<script[\s>]|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie)", lower):
        results.append("⚠ XSS Attack Detected")

    if re.search(r"(\b(cmd\.exe|powershell(\.exe)?|/bin/(ba)?sh)\b|cmd=|exec\(|;\s*(cat|whoami|id)\b)", lower):
        results.append("⚠ Command Injection Detected")

    if "../" in lower or "..\\" in lower:
        results.append("⚠ Directory Traversal Detected")

    if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", data):
        results.append("🌐 IP Address Found in Packet")

    if "base64" in lower:
        results.append("⚠ Encoded Payload Detected")

    if "password" in lower or "passwd" in lower:
        results.append("🔐 Sensitive Data Detected")

    results.append("📦 Packet Length: " + str(len(data)))
    results.append("📡 Protocol Guess: HTTP/TCP")
    if len(results) == 2:
        results.append("✅ No Major Threat Found")
    return results


def _packet_line(i, pkt):
    src = dst = '-'
    proto = pkt.__class__.__name__.upper()
    info = ''
    if IP is not None and pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
        if TCP is not None and pkt.haslayer(TCP):
            proto = 'TCP'
            info = f"{pkt[TCP].sport} → {pkt[TCP].dport} flags={pkt[TCP].flags}"
        elif UDP is not None and pkt.haslayer(UDP):
            proto = 'UDP'
            info = f"{pkt[UDP].sport} → {pkt[UDP].dport}"
        elif ICMP is not None and pkt.haslayer(ICMP):
            proto = 'ICMP'
    elif ARP is not None and pkt.haslayer(ARP):
        proto = 'ARP'; src = pkt[ARP].psrc; dst = pkt[ARP].pdst
    payload = ''
    try:
        if Raw is not None and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load).decode(errors='ignore')[:500]
    except Exception:
        pass
    combined = f"{src} {dst} {proto} {info} {payload}"
    threats = analyze_packet(combined)
    return f"Packet {i}: {src} → {dst} | {proto} | {len(pkt)} bytes | {info or 'no transport metadata'} | {' ; '.join(threats)}"


def analyze_packet_file(path):
    ext = path.lower()
    if ext.endswith(('.pcap', '.pcapng', '.cap')) and rdpcap is not None:
        try:
            packets = rdpcap(path)
            total = len(packets)
            # Cap to first 1000 packets to prevent excessive memory/CPU consumption
            max_packets = min(total, 1000)
            results = [f"📡 Capture loaded: {total} packets (analyzing first {max_packets})"]
            for i in range(max_packets):
                results.append(_packet_line(i + 1, packets[i]))
            if total == 0:
                results.append("ℹ Empty capture")
            elif total > max_packets:
                results.append(f"ℹ Truncated: {total - max_packets} additional packets not displayed")
            return results
        except Exception as e:
            return [f"❌ PCAP parsing error: {e}"]
    try:
        # Cap file read to 5MB to prevent memory exhaustion / OOM
        MAX_BYTES = 5 * 1024 * 1024
        with open(path, 'rb') as f:
            content = f.read(MAX_BYTES)
        return analyze_packet(content.decode(errors='ignore'))
    except Exception as e:
        return [f"❌ Error reading file: {e}"]
