def analyze_log(file_path):
    total_logs = 0
    ip_count = {}
    suspicious_ips = []
    brute_force = 0
    unauthorized = 0

    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            total_logs += 1
 
            parts = line.split()

            if len(parts) > 0:
                ip = parts[0]

                # Count IPs
                if ip not in ip_count:
                    ip_count[ip] = 0
                ip_count[ip] += 1

                # Suspicious (more than 5 hits)
                if ip_count[ip] > 5 and ip not in suspicious_ips:
                    suspicious_ips.append(ip)

            # Brute force detection
            if "failed" in line.lower():
                brute_force += 1

            # Unauthorized access
            if "unauthorized" in line.lower():
                unauthorized += 1

    # Top 5 IPs
    top_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total_logs": total_logs,
        "top_ips": top_ips,
        "suspicious_ips": suspicious_ips,
        "brute_force": brute_force,
        "unauthorized": unauthorized
    }