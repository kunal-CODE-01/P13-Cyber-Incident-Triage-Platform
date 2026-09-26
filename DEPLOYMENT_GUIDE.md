# P13 Cyber Incident Triage Platform — Portable Deployment

This package is designed so the same project can be run on Windows, Linux/VPS, or any server that supports Docker.

## A. Windows PC — one command
1. Open this folder in VS Code.
2. Double-click `run.bat` or run `.run.bat` from CMD/PowerShell (use `./run.bat` if needed).
3. Open `http://127.0.0.1:5000`.

For another device on the same Wi-Fi/LAN, find the host PC IPv4 address with `ipconfig` and open:
`http://HOST-PC-IP:5000`

Allow Python/port 5000 through Windows Firewall when prompted.

## B. Linux VPS — no Docker
```bash
chmod +x run.sh
./run.sh
```
Open `http://SERVER_PUBLIC_IP:5000` after allowing TCP 5000 in the VPS firewall/security group.
For production, place Nginx/Caddy in front and use HTTPS.

## C. Docker — recommended for portability
1. Install Docker + Docker Compose on the server.
2. Copy the project folder to the server.
3. Create `.env` from `.env.example` and set a strong `SECRET_KEY`.
4. Run:
```bash
docker compose up -d --build
```
5. Open `http://SERVER_PUBLIC_IP:5000`.

The Docker image installs Nmap inside the container, so the Python `nmap` module and Nmap executable are both present.

## D. Linux live packet capture
Live Scapy capture requires network privileges. On a Linux host you can use:
```bash
docker compose --profile live-capture up -d --build p13-live
```
Do not expose packet-capture privileges to untrusted users. Use this only on networks you own or are authorized to test.

## E. Nmap requirement
`python-nmap` is the Python wrapper. The actual Nmap executable is also required for Network Scan.
- Windows: install Nmap and ensure `nmap.exe` is in PATH.
- Debian/Ubuntu: `sudo apt-get update && sudo apt-get install -y nmap`
- Docker: already installed by the provided Dockerfile.

## F. Production checklist
- Set a long random `SECRET_KEY`.
- Use HTTPS.
- Do not expose the Flask development server directly to the Internet.
- Put Nginx/Caddy in front of Gunicorn.
- Use persistent storage for `logs`, `reports`, `data`, and the database.
- Restrict upload size/type and keep evidence outside executable paths.
- For multiple concurrent users, migrate SQLite to PostgreSQL and keep the same application layer.
- Never scan systems or networks without authorization.
