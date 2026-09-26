# P13 — Cyber Incident Reporting & Triage Platform

This hackathon version preserves the original dark cyber/SOC UI and existing security-analysis modules while adding the P13 incident-response workflow.

## P13 workflow

Threat / analysis → Incident creation → Severity → Assignment → Investigation → Evidence → Containment → Resolution → Closure → Audit history

## Added P13 features

- Incident reporting and unique incident IDs
- Severity classification: Low / Medium / High / Critical
- Analyst assignment
- Incident status workflow
- Investigation notes
- Evidence register with optional file upload and SHA-256 hash
- Full incident audit timeline
- In-app incident notifications
- Incident queue with filtering
- Incident detail page
- Incident investigation PDF report
- Automatic incident creation from existing log, network, packet, threat and simulation modules
- Existing login, signup, password validation, CAPTCHA UI, Nmap, packet analysis, log analysis, threat intelligence, live capture, analytics and SOC dashboard retained

## Run

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

### Nmap
The network scan module requires Nmap to be installed and available at one of the Windows paths already supported by the project.

### Development admin
The existing development admin configuration from the original project is retained. Change the credential before any real deployment.

## Hackathon demo flow

1. Login.
2. Run Network Scan / Packet Analysis / Log Analysis.
3. The result automatically creates a P13 incident.
4. Open the incident from the result page.
5. Assign an analyst.
6. Add an investigation note.
7. Add evidence and show its SHA-256 hash.
8. Move status: OPEN → ASSIGNED → INVESTIGATING → CONTAINED → RESOLVED → CLOSED.
9. Show the audit timeline.
10. Download the incident investigation report.

## UI PRO Edition
The PRO edition keeps the existing Flask routes and cyber-analysis modules while replacing the legacy neon-terminal interface with a responsive SOC-style command center: fixed navigation, KPI cards, incident queue, triage detail view, evidence register, audit timeline, admin console, live telemetry panels and responsive mobile layout. The visual layer is in `static/p13.css`.


## UI v3 / Live Packet Monitor
The current interface uses the AEGIS SOC visual system with a command-center dashboard, incident queue, evidence workflow, live packet monitor, responsive layouts and operator-focused controls. The Live Packet Monitor captures a bounded sample of IP packets with Scapy and displays source, destination, protocol, ports, length and flags. On hosts without Scapy/Npcap or capture permissions, the dashboard remains usable and the live capture table simply reports no captured packets.

## Nmap dependency
The project includes `python-nmap` in `requirements.txt`. The application starts even when the Python wrapper or Nmap executable is missing; the Network Recon module returns an actionable error instead of crashing the whole application.
