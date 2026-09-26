import re

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, Raw
except Exception:
    rdpcap = IP = TCP = UDP = ICMP = ARP = Raw = None


def analyze_packet(data):
    data = str(data)
    lower = data.lower()
    results = []
    if "select" in lower or "or 1=1" in lower:
        results.append("⚠ SQL Injection Detected")
    if "<script" in lower:
        results.append("⚠ XSS Attack Detected")
    if "cmd=" in lower or "exec" in lower:
        results.append("⚠ Command Injection Detected")
    if "../" in lower:
        results.append("⚠ Directory Traversal Detected")
    if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", data):
        results.append("🌐 IP Address Found in Packet")
    if "base64" in lower:
        results.append("⚠ Encoded Payload Detected")
    if "password" in lower:
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
            results = [f"📡 Capture loaded: {len(packets)} packets"]
            for i, pkt in enumerate(packets, 1):
                results.append(_packet_line(i, pkt))
            if len(packets) == 0:
                results.append("ℹ Empty capture")
            return results
        except Exception as e:
            return [f"❌ PCAP parsing error: {e}"]
    try:
        with open(path, 'rb') as f:
            content = f.read()
        return analyze_packet(content.decode(errors='ignore'))
    except Exception as e:
        return [f"❌ Error reading file: {e}"]
