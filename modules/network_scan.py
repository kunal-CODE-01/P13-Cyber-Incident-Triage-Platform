"""
P13 AEGIS - Network Port Scanner
--------------------------------
Scans the common ports required by the project specification.

Output format is intentionally simple so the existing Flask application
can continue using:

    result = scan_ports(ip)
    len(result)

Each result contains:

    port
    service
    state
    firewall
    response_ms
    detail
"""

import socket
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor


# ============================================================
# COMMON SECURITY / SOC PORT PROFILE
# ============================================================

COMMON_PORTS = [
    {
        "port": 21,
        "service": "FTP",
    },
    {
        "port": 22,
        "service": "SSH",
    },
    {
        "port": 53,
        "service": "DNS",
    },
    {
        "port": 80,
        "service": "HTTP",
    },
    {
        "port": 443,
        "service": "HTTPS",
    },
    {
        "port": 8080,
        "service": "HTTP-Proxy",
    },
    {
        "port": 3306,
        "service": "MySQL",
    },
]


# ============================================================
# CONFIGURATION
# ============================================================

# TCP connect timeout.
# Kept short so the SOC dashboard does not freeze for too long.
CONNECT_TIMEOUT = 1.2


# ============================================================
# TARGET VALIDATION
# ============================================================

def resolve_target(target):
    """
    Resolve an IP address or hostname.

    Returns:
        {
            "ok": True,
            "ip": "...",
            "hostname": "..."
        }

    or:

        {
            "ok": False,
            "error": "..."
        }
    """

    target = str(target or "").strip()

    if not target:
        return {
            "ok": False,
            "error": "Target is required."
        }

    # Prevent extremely long / malformed input.
    if len(target) > 253:
        return {
            "ok": False,
            "error": "Invalid target length."
        }

    resolved_ip = None

    try:
        # Direct IP address.
        ip_obj = ipaddress.ip_address(target)
        resolved_ip = str(ip_obj)
    except ValueError:
        pass

    if not resolved_ip:
        # Hostname / domain.
        try:
            resolved_ip = socket.gethostbyname(target)
            ip_obj = ipaddress.ip_address(resolved_ip)
        except socket.gaierror:
            return {
                "ok": False,
                "error": f"Unable to resolve target: {target}"
            }
        except Exception as exc:
            return {
                "ok": False,
                "error": f"Target resolution failed: {exc}"
            }

    # Security check: Block cloud metadata and dangerous targets
    if ip_obj.is_link_local or resolved_ip.startswith("169.254."):
        return {
            "ok": False,
            "error": "Link-local and cloud metadata addresses (169.254.x.x) are blocked for security."
        }
    if ip_obj.is_multicast:
        return {
            "ok": False,
            "error": "Multicast addresses are blocked."
        }
    if ip_obj.is_reserved:
        return {
            "ok": False,
            "error": "Reserved IP addresses are blocked."
        }

    return {
        "ok": True,
        "ip": resolved_ip,
        "hostname": target
    }


# ============================================================
# SINGLE PORT TEST
# ============================================================

def check_port(ip, port, service):
    """
    Perform a TCP connection test.

    Interpretation:

        connect succeeds
            -> OPEN

        connection refused
            -> CLOSED

        timeout
            -> FILTERED / possibly firewall filtered

        other socket errors
            -> FILTERED / unreachable
    """

    started = time.perf_counter()

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(CONNECT_TIMEOUT)

    try:

        result = sock.connect_ex(
            (ip, port)
        )

        elapsed = round(
            (time.perf_counter() - started) * 1000,
            1
        )

        # ----------------------------------------------------
        # OPEN
        # ----------------------------------------------------

        if result == 0:

            return {
                "port": port,
                "service": service,
                "state": "OPEN",
                "firewall": "NOT FILTERED",
                "response_ms": elapsed,
                "elapsed_ms": elapsed,
                "detail": f"{service} service accepted TCP connection."
            }

        # ----------------------------------------------------
        # CLOSED
        # ----------------------------------------------------

        if result in (
            10061,  # Windows: connection refused
            111,    # Linux: connection refused
        ):

            return {
                "port": port,
                "service": service,
                "state": "CLOSED",
                "firewall": "NO FILTER DETECTED",
                "response_ms": elapsed,
                "elapsed_ms": elapsed,
                "detail": f"{service} port is reachable but no service accepted the connection."
            }

        # ----------------------------------------------------
        # FILTERED
        # ----------------------------------------------------

        return {
            "port": port,
            "service": service,
            "state": "FILTERED",
            "firewall": "POSSIBLE FIREWALL",
            "response_ms": elapsed,
            "elapsed_ms": elapsed,
            "detail": (
                f"No TCP response from {service}. "
                "A firewall, ACL, host filter, or network path may be filtering traffic."
            )
        }

    except socket.timeout:

        elapsed = round(
            (time.perf_counter() - started) * 1000,
            1
        )

        return {
            "port": port,
            "service": service,
            "state": "FILTERED",
            "firewall": "POSSIBLE FIREWALL",
            "response_ms": elapsed,
            "elapsed_ms": elapsed,
            "detail": (
                f"{service} connection timed out. "
                "Possible stateful firewall or packet filtering."
            )
        }

    except ConnectionRefusedError:

        elapsed = round(
            (time.perf_counter() - started) * 1000,
            1
        )

        return {
            "port": port,
            "service": service,
            "state": "CLOSED",
            "firewall": "NO FILTER DETECTED",
            "response_ms": elapsed,
            "elapsed_ms": elapsed,
            "detail": f"{service} actively refused the connection."
        }

    except OSError as exc:

        elapsed = round(
            (time.perf_counter() - started) * 1000,
            1
        )

        return {
            "port": port,
            "service": service,
            "state": "FILTERED",
            "firewall": "POSSIBLE FILTER",
            "response_ms": elapsed,
            "elapsed_ms": elapsed,
            "detail": f"Socket error: {exc}"
        }

    finally:

        try:
            sock.close()
        except Exception:
            pass


# ============================================================
# MAIN SCANNER
# ============================================================

def scan_ports(target):
    """
    Scan all required common ports.

    Returns a list of dictionaries.

    Example:

        [
            {
                "port": 22,
                "service": "SSH",
                "state": "OPEN",
                "firewall": "NOT FILTERED",
                "response_ms": 4.2,
                "elapsed_ms": 4.2,
                "detail": "..."
            },
            ...
        ]
    """

    resolved = resolve_target(target)

    if not resolved["ok"]:

        return [
            {
                "port": "-",
                "service": "Target",
                "state": "ERROR",
                "firewall": "N/A",
                "response_ms": 0,
                "elapsed_ms": 0,
                "detail": resolved["error"]
            }
        ]

    ip = resolved["ip"]

    results = []

    # --------------------------------------------------------
    # Scan ports concurrently (reduces scan latency from ~8.4s to ~1.2s)
    # --------------------------------------------------------
    with ThreadPoolExecutor(max_workers=min(len(COMMON_PORTS), 16)) as executor:
        futures = [
            executor.submit(check_port, ip, item["port"], item["service"])
            for item in COMMON_PORTS
        ]
        for future in futures:
            try:
                results.append(future.result())
            except Exception as exc:
                pass

    # --------------------------------------------------------
    # Sort by port number
    # --------------------------------------------------------
    results.sort(
        key=lambda x: (
            x["port"]
            if isinstance(x["port"], int)
            else 99999
        )
    )

    return results


# ============================================================
# SOC SUMMARY
# ============================================================

def scan_summary(results):
    """
    Generate a compact SOC-style summary from scan results.

    This helper is useful for the future Integrated Incident
    Triage screen.
    """

    if not isinstance(results, list):
        results = []

    open_ports = [
        item for item in results
        if item.get("state") == "OPEN"
    ]

    closed_ports = [
        item for item in results
        if item.get("state") == "CLOSED"
    ]

    filtered_ports = [
        item for item in results
        if item.get("state") == "FILTERED"
    ]

    return {
        "total": len(results),
        "open": len(open_ports),
        "closed": len(closed_ports),
        "filtered": len(filtered_ports),
        "open_ports": [
            item.get("port")
            for item in open_ports
        ],
        "filtered_ports": [
            item.get("port")
            for item in filtered_ports
        ],
    }


# ============================================================
# COMMAND-LINE TEST
# ============================================================

if __name__ == "__main__":

    import sys

    target = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "127.0.0.1"
    )

    print()
    print("=" * 78)
    print("P13 AEGIS NETWORK SCAN")
    print("=" * 78)
    print(f"Target: {target}")
    print()

    results = scan_ports(target)

    print(
        f"{'PORT':<8}"
        f"{'SERVICE':<16}"
        f"{'STATE':<12}"
        f"{'FIREWALL':<22}"
        f"{'TIME':<10}"
    )

    print("-" * 78)

    for item in results:

        print(
            f"{str(item['port']):<8}"
            f"{item['service']:<16}"
            f"{item['state']:<12}"
            f"{item['firewall']:<22}"
            f"{str(item['response_ms']) + ' ms':<10}"
        )

    print("-" * 78)

    summary = scan_summary(results)

    print(
        f"Total: {summary['total']} | "
        f"Open: {summary['open']} | "
        f"Closed: {summary['closed']} | "
        f"Filtered: {summary['filtered']}"
    )

    print("=" * 78)