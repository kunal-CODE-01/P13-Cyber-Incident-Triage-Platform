"""
Database management helper for P13 Cyber Incident Triage Platform.
Delegates to the authoritative database initialization in app.py.
"""
import os
import sys

# Ensure project root is in path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

def init_db():
    try:
        from app import init_db as app_init_db
        app_init_db()
        print("[+] Database initialized successfully with WAL mode, tables, indexes, and admin account.")
    except Exception as exc:
        print(f"[-] Database initialization failed: {exc}")
        raise

if __name__ == "__main__":
    init_db()