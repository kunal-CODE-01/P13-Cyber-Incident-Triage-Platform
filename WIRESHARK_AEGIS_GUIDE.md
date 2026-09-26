# Wireshark → AEGIS

1. Open Wireshark and capture on your permitted interface.
2. Stop the capture.
3. File → Save As → save as `.pcap` or `.pcapng`.
4. In AEGIS Command Center open **PCAP / Packet Forensics**.
5. Upload the capture and click **Import & Analyze**.
6. AEGIS parses the capture with Scapy, lists packet metadata and checks payload text for the project's explainable indicators.

For live monitoring, use **Live Packet Monitor** in AEGIS. It captures traffic on the machine/interface where AEGIS is running. On Windows, Npcap and appropriate permissions are required.
