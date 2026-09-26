"""
AEGIS P13 - Live Packet Capture Engine

Features:
- Real-time packet capture using Scapy
- TCP / UDP / ICMP / ARP detection
- Source / destination IP
- Source / destination ports
- TCP flags
- Packet length
- Risk detection
- Packet search/filter
- Threaded capture
- Ring buffer
- Packet inspector
- Compatibility function: capture_packets()

Requirements:
    pip install scapy

Windows:
    Install Npcap and allow WinPcap-compatible API if requested.

IMPORTANT:
    Capture only traffic on systems/networks you own or are authorized
    to monitor.
"""

from collections import deque
from datetime import datetime
import threading
import time
import os
import sqlite3

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DB_PATH = os.path.join(_BASE_DIR, "users.db")

def _get_db():
    conn = sqlite3.connect(_DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    return conn

def _init_packet_db():
    try:
        conn = _get_db()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS live_packet_buffer (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT,
                timestamp TEXT,
                src TEXT,
                dst TEXT,
                protocol TEXT,
                sport TEXT,
                dport TEXT,
                length INTEGER,
                flags TEXT,
                ttl TEXT,
                src_mac TEXT,
                dst_mac TEXT,
                risk TEXT,
                info TEXT,
                payload_length INTEGER,
                payload_preview TEXT,
                hex_preview TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS live_capture_meta (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_live_pkt_id ON live_packet_buffer(id DESC);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_live_pkt_proto ON live_packet_buffer(protocol);")
        conn.commit()
        conn.close()
    except Exception:
        pass

_init_packet_db()


# ============================================================
# SCAPY IMPORT
# ============================================================

try:

    from scapy.all import (
        sniff,
        IP,
        TCP,
        UDP,
        ICMP,
        ARP,
        Raw,
        Ether,
        get_if_list,
    )

    SCAPY_AVAILABLE = True

except Exception as exc:

    sniff = None
    IP = None
    TCP = None
    UDP = None
    ICMP = None
    ARP = None
    Raw = None
    Ether = None

    def get_if_list():
        return []

    SCAPY_AVAILABLE = False

    SCAPY_ERROR = str(exc)


# ============================================================
# GLOBAL STATE
# ============================================================

_lock = threading.RLock()

_packets = deque(maxlen=5000)

_running = False

_thread = None

_stop_event = threading.Event()

_sequence = 0

_current_interface = None

_last_error = None

_started_at = None


# ============================================================
# BASIC STATUS
# ============================================================

def available():
    """
    Returns True when Scapy successfully imported.
    """

    return SCAPY_AVAILABLE


# ============================================================
# NETWORK INTERFACES
# ============================================================

def interfaces():
    """
    Return available Scapy/Npcap interfaces.

    Example Windows output:

        \\Device\\NPF_{XXXX-XXXX}

    """

    if not SCAPY_AVAILABLE:
        return []

    try:

        result = get_if_list()

        cleaned = []

        for interface in result:

            if interface and interface not in cleaned:

                cleaned.append(interface)

        return cleaned

    except Exception:

        return []


# ============================================================
# PROTOCOL DETECTION
# ============================================================

def _protocol(pkt):

    try:

        if IP is not None and pkt.haslayer(IP):

            if TCP is not None and pkt.haslayer(TCP):
                return "TCP"

            if UDP is not None and pkt.haslayer(UDP):
                return "UDP"

            if ICMP is not None and pkt.haslayer(ICMP):
                return "ICMP"

            return "IP"

        if ARP is not None and pkt.haslayer(ARP):
            return "ARP"

        if Ether is not None and pkt.haslayer(Ether):
            return "ETHERNET"

    except Exception:
        pass

    return "OTHER"


# ============================================================
# RISK / THREAT DETECTION
# ============================================================

def _risk(pkt):

    """
    Passive and explainable packet indicators.

    This does NOT modify or block traffic.
    """

    payload_text = ""

    try:

        if Raw is not None and pkt.haslayer(Raw):

            raw_data = bytes(pkt[Raw].load)

            payload_text = raw_data.decode(
                "utf-8",
                errors="ignore"
            ).lower()

    except Exception:

        payload_text = ""

    indicators = [

        (
            "select ",
            "HIGH",
            "SQL injection-like pattern"
        ),

        (
            "union select",
            "HIGH",
            "SQL injection-like pattern"
        ),

        (
            "<script",
            "HIGH",
            "XSS-like pattern"
        ),

        (
            "javascript:",
            "HIGH",
            "JavaScript injection-like pattern"
        ),

        (
            "../",
            "HIGH",
            "Directory traversal-like pattern"
        ),

        (
            "..\\",
            "HIGH",
            "Directory traversal-like pattern"
        ),

        (
            "cmd=",
            "HIGH",
            "Command injection-like pattern"
        ),

        (
            "powershell",
            "HIGH",
            "PowerShell execution marker"
        ),

        (
            "password",
            "MEDIUM",
            "Credential field observed"
        ),

        (
            "passwd",
            "MEDIUM",
            "Password file indicator"
        ),

        (
            "base64",
            "MEDIUM",
            "Encoded payload marker"
        ),

    ]

    for needle, severity, reason in indicators:

        if needle in payload_text:

            return severity, reason

    return "NORMAL", ""


# ============================================================
# PACKET INFORMATION
# ============================================================

def _packet_info(pkt, protocol, src, dst, sport, dport, flags):

    """
    Generate Wireshark-style Info field.
    """

    try:

        if protocol == "TCP":

            if flags:

                return (
                    f"{sport} → {dport} "
                    f"[{flags}]"
                )

            return f"{sport} → {dport}"

        if protocol == "UDP":

            return f"{sport} → {dport}"

        if protocol == "ICMP":

            icmp_type = "-"

            try:

                icmp_type = pkt[ICMP].type

            except Exception:
                pass

            return f"ICMP type={icmp_type}"

        if protocol == "ARP":

            return (
                f"Who has {dst}? "
                f"Tell {src}"
            )

        if protocol == "IP":

            return f"{src} → {dst}"

    except Exception:
        pass

    return f"{protocol} {src} → {dst}"


# ============================================================
# PACKET RECORD
# ============================================================

def _record(pkt):

    global _sequence

    try:

        if isinstance(pkt, dict):
            _sequence += 1
            record = {
                "id": _sequence,
                "time": pkt.get("time", datetime.now().strftime("%H:%M:%S.%f")[:-3]),
                "timestamp": pkt.get("timestamp", datetime.now().isoformat()),
                "src": str(pkt.get("src", "-")),
                "dst": str(pkt.get("dst", "-")),
                "protocol": str(pkt.get("protocol", "OTHER")),
                "sport": pkt.get("sport", "-"),
                "dport": pkt.get("dport", "-"),
                "flags": pkt.get("flags", "-"),
                "length": int(pkt.get("length", 0)),
                "ttl": pkt.get("ttl", "-"),
                "src_mac": pkt.get("src_mac", "-"),
                "dst_mac": pkt.get("dst_mac", "-"),
                "info": pkt.get("info", ""),
                "risk": pkt.get("risk", "NORMAL"),
                "payload_preview": pkt.get("payload_preview", ""),
                "payload_length": int(pkt.get("payload_length", 0)),
                "hex_preview": pkt.get("hex_preview", "")
            }
            with _lock:
                _packets.append(record)
                if len(_packets) > MAX_PACKETS:
                    _packets.pop(0)
            try:
                conn = _get_db()
                conn.execute("""
                    INSERT INTO live_packet_buffer 
                    (id, time, timestamp, src, dst, protocol, sport, dport, flags, length, ttl, src_mac, dst_mac, info, risk, payload_preview, payload_length, hex_preview)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record["id"], record["time"], record["timestamp"], record["src"], record["dst"],
                    record["protocol"], str(record["sport"]), str(record["dport"]), record["flags"],
                    record["length"], str(record["ttl"]), record["src_mac"], record["dst_mac"],
                    record["info"], record["risk"], record["payload_preview"], record["payload_length"], record["hex_preview"]
                ))
                conn.execute("DELETE FROM live_packet_buffer WHERE id NOT IN (SELECT id FROM live_packet_buffer ORDER BY id DESC LIMIT 500)")
                conn.commit()
                conn.close()
            except Exception:
                pass
            return

        _sequence += 1

        packet_id = _sequence

        timestamp = datetime.now()

        time_string = timestamp.strftime(
            "%H:%M:%S.%f"
        )[:-3]

        protocol = _protocol(pkt)

        src = "-"

        dst = "-"

        sport = "-"

        dport = "-"

        flags = "-"

        ttl = "-"

        src_mac = "-"

        dst_mac = "-"

        # ----------------------------------------------------
        # Ethernet
        # ----------------------------------------------------

        try:

            if Ether is not None and pkt.haslayer(Ether):

                src_mac = pkt[Ether].src

                dst_mac = pkt[Ether].dst

        except Exception:
            pass

        # ----------------------------------------------------
        # IPv4
        # ----------------------------------------------------

        if IP is not None and pkt.haslayer(IP):

            ip = pkt[IP]

            src = ip.src

            dst = ip.dst

            ttl = getattr(
                ip,
                "ttl",
                "-"
            )

        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        if TCP is not None and pkt.haslayer(TCP):

            tcp = pkt[TCP]

            sport = int(
                getattr(
                    tcp,
                    "sport",
                    0
                )
            )

            dport = int(
                getattr(
                    tcp,
                    "dport",
                    0
                )
            )

            flags = str(
                getattr(
                    tcp,
                    "flags",
                    "-"
                )
            )

        # ----------------------------------------------------
        # UDP
        # ----------------------------------------------------

        elif UDP is not None and pkt.haslayer(UDP):

            udp = pkt[UDP]

            sport = int(
                getattr(
                    udp,
                    "sport",
                    0
                )
            )

            dport = int(
                getattr(
                    udp,
                    "dport",
                    0
                )
            )

        # ----------------------------------------------------
        # ARP
        # ----------------------------------------------------

        if ARP is not None and pkt.haslayer(ARP):

            arp = pkt[ARP]

            src = getattr(
                arp,
                "psrc",
                "-"
            )

            dst = getattr(
                arp,
                "pdst",
                "-"
            )

        # ----------------------------------------------------
        # RISK
        # ----------------------------------------------------

        risk, reason = _risk(pkt)

        # ----------------------------------------------------
        # INFO
        # ----------------------------------------------------

        info = _packet_info(
            pkt,
            protocol,
            src,
            dst,
            sport,
            dport,
            flags
        )

        if reason:

            info = (
                f"{reason} | "
                f"{info}"
            )

        # ----------------------------------------------------
        # RAW PAYLOAD METADATA
        # ----------------------------------------------------

        payload_length = 0

        payload_preview = ""

        try:

            if Raw is not None and pkt.haslayer(Raw):

                raw_bytes = bytes(
                    pkt[Raw].load
                )

                payload_length = len(
                    raw_bytes
                )

                payload_preview = (
                    raw_bytes[:120]
                    .decode(
                        "utf-8",
                        errors="replace"
                    )
                )

        except Exception:

            pass

        # ----------------------------------------------------
        # HEX PREVIEW
        # ----------------------------------------------------

        hex_preview = ""

        try:

            raw_bytes = bytes(pkt)

            hex_preview = (
                raw_bytes[:64]
                .hex(" ")
            )

        except Exception:

            pass

        # ----------------------------------------------------
        # FINAL RECORD
        # ----------------------------------------------------

        record = {

            "id": packet_id,

            "time": time_string,

            "timestamp": timestamp.isoformat(),

            "src": str(src),

            "dst": str(dst),

            "protocol": protocol,

            "sport": sport,

            "dport": dport,

            "length": len(pkt),

            "flags": flags,

            "ttl": ttl,

            "src_mac": str(src_mac),

            "dst_mac": str(dst_mac),

            "risk": risk,

            "info": info,

            "payload_length": payload_length,

            "payload_preview": payload_preview,

            "hex_preview": hex_preview,

        }

        # ----------------------------------------------------
        # STORE
        # ----------------------------------------------------

        with _lock:

            _packets.appendleft(
                record
            )

        try:
            conn = _get_db()
            conn.execute("""
                INSERT INTO live_packet_buffer 
                (time, timestamp, src, dst, protocol, sport, dport, length, flags, ttl, src_mac, dst_mac, risk, info, payload_length, payload_preview, hex_preview)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record["time"], record["timestamp"], record["src"], record["dst"],
                record["protocol"], str(record["sport"]), str(record["dport"]),
                record["length"], record["flags"], str(record["ttl"]),
                record["src_mac"], record["dst_mac"], record["risk"], record["info"],
                record["payload_length"], record["payload_preview"], record["hex_preview"]
            ))
            if _sequence % 200 == 0:
                conn.execute("DELETE FROM live_packet_buffer WHERE id NOT IN (SELECT id FROM live_packet_buffer ORDER BY id DESC LIMIT 5000)")
            conn.commit()
            conn.close()
        except Exception:
            pass

        return record

    except Exception as exc:

        return {

            "id": -1,

            "time": datetime.now().strftime(
                "%H:%M:%S.%f"
            )[:-3],

            "src": "-",

            "dst": "-",

            "protocol": "ERROR",

            "sport": "-",

            "dport": "-",

            "length": 0,

            "flags": "-",

            "ttl": "-",

            "src_mac": "-",

            "dst_mac": "-",

            "risk": "MEDIUM",

            "info": (
                "Packet parsing error: "
                + str(exc)
            ),

            "payload_length": 0,

            "payload_preview": "",

            "hex_preview": "",

        }


# ============================================================
# CAPTURE WORKER
# ============================================================

def _worker(interface):

    global _running

    global _last_error

    try:

        while not _stop_event.is_set():

            try:
                conn = _get_db()
                row = conn.execute("SELECT value FROM live_capture_meta WHERE key = 'running'").fetchone()
                conn.close()
                if row and row[0] == "0":
                    break
            except Exception:
                pass

            sniff(

                iface=interface or None,

                prn=_record,

                store=False,

                timeout=1

            )

    except Exception as exc:

        _last_error = str(exc)

    finally:

        _running = False
        try:
            conn = _get_db()
            conn.execute("INSERT OR REPLACE INTO live_capture_meta (key, value) VALUES ('running', '0')")
            conn.commit()
            conn.close()
        except Exception:
            pass


# ============================================================
# START CAPTURE
# ============================================================

def start_capture(iface=None):

    global _running

    global _thread

    global _current_interface

    global _last_error

    global _started_at

    if not SCAPY_AVAILABLE:

        return {

            "ok": False,

            "running": False,

            "error": (
                "Scapy is unavailable. "
                "Install it with: "
                "pip install scapy"
            )

        }

    with _lock:

        if _running:

            return {

                "ok": True,

                "running": True,

                "interface":
                    _current_interface

            }

    # --------------------------------------------------------
    # Interface validation
    # --------------------------------------------------------

    available_interfaces = interfaces()

    selected_interface = (
        iface.strip()
        if isinstance(iface, str)
        and iface.strip()
        else None
    )

    if selected_interface:

        if (
            available_interfaces
            and selected_interface
            not in available_interfaces
        ):

            return {

                "ok": False,

                "running": False,

                "error": (
                    "Selected network interface "
                    "was not found by Scapy."
                )

            }

    # --------------------------------------------------------
    # Reset
    # --------------------------------------------------------

    _stop_event.clear()

    _last_error = None

    _current_interface = (
        selected_interface
    )

    _started_at = (
        datetime.now().isoformat()
    )

    _running = True

    try:
        conn = _get_db()
        conn.execute("INSERT OR REPLACE INTO live_capture_meta (key, value) VALUES ('running', '1')")
        conn.execute("INSERT OR REPLACE INTO live_capture_meta (key, value) VALUES ('interface', ?)", (str(selected_interface or ''),))
        conn.execute("INSERT OR REPLACE INTO live_capture_meta (key, value) VALUES ('started_at', ?)", (str(_started_at),))
        conn.commit()
        conn.close()
    except Exception:
        pass

    # --------------------------------------------------------
    # Capture thread
    # --------------------------------------------------------

    _thread = threading.Thread(

        target=_worker,

        args=(
            _current_interface,
        ),

        daemon=True,

        name="AEGIS-LIVE-PACKET-CAPTURE"

    )

    _thread.start()

    time.sleep(0.15)

    return {

        "ok": True,

        "running": True,

        "interface":
            _current_interface,

        "started_at":
            _started_at

    }


# ============================================================
# STOP CAPTURE
# ============================================================

def stop_capture():

    global _running

    _stop_event.set()

    _running = False

    try:
        conn = _get_db()
        conn.execute("INSERT OR REPLACE INTO live_capture_meta (key, value) VALUES ('running', '0')")
        conn.commit()
        conn.close()
    except Exception:
        pass

    return {

        "ok": True,

        "running": False

    }


# ============================================================
# STATUS
# ============================================================

def status():

    is_running = _running
    meta_iface = _current_interface
    meta_started = _started_at
    meta_err = _last_error
    count = len(_packets)

    try:
        conn = _get_db()
        rows = dict(conn.execute("SELECT key, value FROM live_capture_meta").fetchall())
        count = conn.execute("SELECT COUNT(*) FROM live_packet_buffer").fetchone()[0]
        conn.close()
        if rows.get("running") == "1":
            is_running = True
            meta_iface = rows.get("interface") or meta_iface
            meta_started = rows.get("started_at") or meta_started
        elif rows.get("running") == "0":
            is_running = False
    except Exception:
        pass

    return {

        "available":
            SCAPY_AVAILABLE,

        "running":
            is_running,

        "interface":
            meta_iface,

        "error":
            meta_err,

        "count":
            count,

        "started_at":
            meta_started,

    }


# ============================================================
# GET PACKETS
# ============================================================

def get_packets(
    limit=300,
    protocol="ALL",
    query=""
):

    protocol = (
        str(protocol or "ALL")
        .upper()
        .strip()
    )

    query = (
        str(query or "")
        .lower()
        .strip()
    )

    try:

        limit = int(limit)

    except Exception:

        limit = 300

    limit = max(
        1,
        min(limit, 2000)
    )

    # First attempt to read from shared SQLite buffer
    try:
        conn = _get_db()
        sql = "SELECT * FROM live_packet_buffer WHERE 1=1"
        params = []
        if protocol != "ALL":
            sql += " AND protocol = ?"
            params.append(protocol)
        if query:
            sql += " AND (lower(src) LIKE ? OR lower(dst) LIKE ? OR lower(protocol) LIKE ? OR lower(info) LIKE ? OR lower(payload_preview) LIKE ?)"
            q_param = f"%{query}%"
            params.extend([q_param, q_param, q_param, q_param, q_param])
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        if rows:
            return [dict(r) for r in rows]
    except Exception:
        pass

    with _lock:

        data = list(
            _packets
        )

    # --------------------------------------------------------
    # Protocol filter
    # --------------------------------------------------------

    if protocol != "ALL":

        data = [

            packet

            for packet in data

            if packet.get(
                "protocol"
            ) == protocol

        ]

    # --------------------------------------------------------
    # Search filter
    # --------------------------------------------------------

    if query:

        filtered = []

        for packet in data:

            searchable = " ".join(

                str(
                    packet.get(
                        key,
                        ""
                    )
                )

                for key in [

                    "id",
                    "time",
                    "src",
                    "dst",
                    "protocol",
                    "sport",
                    "dport",
                    "length",
                    "flags",
                    "risk",
                    "info",
                    "payload_preview",

                ]

            ).lower()

            if query in searchable:

                filtered.append(
                    packet
                )

        data = filtered

    return data[:limit]


# ============================================================
# GET SINGLE PACKET
# ============================================================

def get_packet(packet_id):

    try:

        packet_id = int(
            packet_id
        )

    except Exception:

        return None

    try:
        conn = _get_db()
        row = conn.execute("SELECT * FROM live_packet_buffer WHERE id = ?", (packet_id,)).fetchone()
        conn.close()
        if row:
            return dict(row)
    except Exception:
        pass

    with _lock:

        for packet in _packets:

            if int(
                packet.get(
                    "id",
                    -1
                )
            ) == packet_id:

                return packet

    return None


# ============================================================
# CLEAR BUFFER
# ============================================================

def clear_packets():

    global _sequence

    with _lock:

        _packets.clear()

        _sequence = 0

    try:
        conn = _get_db()
        conn.execute("DELETE FROM live_packet_buffer")
        conn.commit()
        conn.close()
    except Exception:
        pass

    return {

        "ok": True,

        "count": 0

    }


# ============================================================
# COMPATIBILITY FUNCTION
# ============================================================

def capture_packets(
    iface=None,
    timeout=10,
    count=0
):

    """
    Compatibility helper.

    Starts live capture for a limited time and
    returns captured packets.

    Example:

        capture_packets(
            iface="Wi-Fi",
            timeout=10
        )
    """

    result = start_capture(
        iface
    )

    if not result.get(
        "ok"
    ):

        return []

    start_time = time.time()

    while True:

        # ----------------------------------------------------
        # Stop after timeout
        # ----------------------------------------------------

        if (
            time.time()
            - start_time
            >= float(timeout)
        ):

            break

        # ----------------------------------------------------
        # Stop after requested packet count
        # ----------------------------------------------------

        if count:

            with _lock:

                current_count = len(
                    _packets
                )

            if current_count >= count:

                break

        time.sleep(
            0.1
        )

    stop_capture()

    return get_packets(
        limit=1000
    )


# ============================================================
# SHUTDOWN SAFETY
# ============================================================

def shutdown():

    try:

        stop_capture()

    except Exception:

        pass