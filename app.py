from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    send_file,
    url_for,
    jsonify
)

import os
import datetime
import time
import sqlite3
import re
import hashlib
import uuid
import urllib.parse
import requests
import socket
import io
import secrets
from functools import wraps

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

from reportlab.pdfgen import canvas


# ============================================================
# SECURITY / ANALYSIS MODULES
# ============================================================

from modules.log_analysis import analyze_log
from modules.network_scan import (
    scan_ports,
    resolve_target
)
from modules.packet_analysis import (
    analyze_packet,
    analyze_packet_file
)

from modules.live_packet import (
    capture_packets,
    start_capture,
    stop_capture,
    status as live_status,
    get_packets,
    get_packet,
    interfaces as live_interfaces,
    clear_packets
)

from modules.threat_intel import analyze_threat


# ============================================================
# APP
# ============================================================

app = Flask(__name__)
# Enable reverse-proxy header support for correct client IP detection
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Always load the project's own .env file.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE_DIR, ".env"), override=True)
except Exception:
    pass


# ============================================================
# CONFIGURATION
# ============================================================

# Secure Secret Key: Ensure it's not a predictable default
_env_secret = os.getenv("SECRET_KEY", "").strip()
if not _env_secret or _env_secret in ("p13-change-this-secret", "p13-aegis-secure-key-2026-change-this-later", "change-this-secret"):
    _secret_dir = os.path.join(BASE_DIR, "data")
    os.makedirs(_secret_dir, exist_ok=True)
    _secret_file = os.path.join(_secret_dir, "secret_key.bin")
    if os.path.exists(_secret_file):
        with open(_secret_file, "rb") as _f:
            app.secret_key = _f.read()
    else:
        app.secret_key = secrets.token_bytes(32)
        try:
            with open(_secret_file, "wb") as _f:
                _f.write(app.secret_key)
        except Exception:
            pass
else:
    app.secret_key = _env_secret

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=8),
    MAX_CONTENT_LENGTH=32 * 1024 * 1024  # 32 MB max file size
)

GOOGLE_CLIENT_ID = os.getenv(
    "GOOGLE_CLIENT_ID",
    ""
)

GOOGLE_CLIENT_SECRET = os.getenv(
    "GOOGLE_CLIENT_SECRET",
    ""
)

GOOGLE_REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    ""
)


# ============================================================
# GOOGLE OAUTH
# ============================================================

def google_configured():

    return bool(
        GOOGLE_CLIENT_ID
        and GOOGLE_CLIENT_SECRET
        and GOOGLE_REDIRECT_URI
    )


# ============================================================
# GLOBAL UI READABILITY
# ============================================================
# Keeps the existing dark AEGIS design but increases text size,
# contrast, spacing and table readability across HTML pages.
READABILITY_CSS = """
<style id="aegis-readability">
:root {
    --aegis-text: #e8f0f7;
    --aegis-muted: #a9bbca;
    --aegis-border: rgba(120, 170, 200, .24);
}

html {
    font-size: 16px;
}

body {
    font-size: 15px !important;
    line-height: 1.55 !important;
    letter-spacing: .01em;
}

p, li, td, th, label, option, select,
input, textarea, button {
    font-size: 14px !important;
    line-height: 1.45 !important;
}

p, li, td, th, label {
    color: var(--aegis-text);
}

small, .small, .muted, .subtitle, .caption,
.helper, .hint, .description {
    font-size: 13px !important;
    line-height: 1.5 !important;
    color: var(--aegis-muted) !important;
}

input, textarea, select {
    min-height: 42px;
    padding: 9px 12px !important;
}

textarea {
    min-height: 100px;
}

button, .btn, a.button, input[type="submit"] {
    min-height: 42px;
    padding: 9px 14px !important;
    font-weight: 600 !important;
}

table {
    font-size: 14px !important;
}

table th {
    font-size: 13px !important;
    font-weight: 700 !important;
    letter-spacing: .03em;
}

table td {
    font-size: 14px !important;
    padding: 10px 12px !important;
}

h1 {
    font-size: clamp(28px, 3vw, 40px) !important;
    line-height: 1.15 !important;
}

h2 {
    font-size: clamp(22px, 2.2vw, 30px) !important;
    line-height: 1.2 !important;
}

h3 {
    font-size: 19px !important;
    line-height: 1.25 !important;
}

nav a, header a, .nav-link, .sidebar a {
    font-size: 14px !important;
}

pre, code, .mono, .packet-data, .packet-details,
.log-output, .terminal-output {
    font-size: 13px !important;
    line-height: 1.55 !important;
}

/* Live packet / Wireshark-style tables */
.packet-table,
.packet-table td,
.packet-table th,
.live-table,
.live-table td,
.live-table th {
    font-size: 14px !important;
}

.packet-table td,
.live-table td {
    padding-top: 9px !important;
    padding-bottom: 9px !important;
}

/* Improve long incident/security text wrapping. */
.card, .panel, .section, .content, .description {
    overflow-wrap: anywhere;
}
</style>
"""


def get_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


@app.context_processor
def inject_template_globals():
    return {
        "csrf_token": get_csrf_token(),
        "google_enabled": google_configured()
    }


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Authentication required"}), 401
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect("/")
        if session.get("role") != "admin":
            return "Access Denied: Administrator role required", 403
        return f(*args, **kwargs)
    return decorated_function


ALLOWED_EXTENSIONS = {
    'log': {'.log', '.txt', '.csv', '.json'},
    'packet': {'.pcap', '.pcapng', '.cap', '.txt', '.log'},
    'evidence': {'.pcap', '.pcapng', '.cap', '.log', '.txt', '.csv', '.json', '.png', '.jpg', '.jpeg', '.pdf'}
}


def is_allowed_file(filename, category='evidence'):
    ext = os.path.splitext(str(filename or "").lower())[1]
    return ext in ALLOWED_EXTENSIONS.get(category, set())


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.endpoint in ("login", "signup", "google_login", "google_callback"):
            return

        expected_token = session.get("_csrf_token")
        provided_token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken") or request.headers.get("X-CSRF-Token")

        if expected_token and provided_token and secrets.compare_digest(str(expected_token), str(provided_token)):
            return

        # Safe fallback for same-origin JSON requests from active session
        if (request.is_json or request.path.startswith("/api/")) and "user" in session:
            sec_fetch = request.headers.get("Sec-Fetch-Site")
            if sec_fetch in ("same-origin", "same-site", None):
                return

        if request.is_json or request.path.startswith("/api/"):
            return jsonify({"ok": False, "error": "Invalid or missing CSRF token"}), 403

        return render_template("login.html", error="Session expired or invalid form signature. Please try again.", google_enabled=google_configured()), 403


@app.after_request
def inject_readability_css(response):
    """Inject the global readability CSS, CSRF tokens, and security headers into HTML responses only."""
    content_type = (response.content_type or "").lower()

    if (
        "text/html" in content_type
        and response.status_code < 400
        and response.direct_passthrough is False
    ):
        try:
            html = response.get_data(as_text=True)
            modified = False
            if "</head>" in html.lower() and "aegis-readability" not in html:
                idx = html.lower().rfind("</head>")
                html = html[:idx] + READABILITY_CSS + html[idx:]
                modified = True

            # Auto-inject CSRF token into HTML forms
            if "<form" in html.lower() and 'name="csrf_token"' not in html:
                token = get_csrf_token()
                csrf_tag = f'<input type="hidden" name="csrf_token" value="{token}">'
                html = re.sub(r'(<form\b[^>]*>)', r'\1' + csrf_tag, html, flags=re.IGNORECASE)
                modified = True

            if modified:
                response.set_data(html)
        except Exception:
            # Never let UI enhancement break the actual application response.
            pass

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


def google_authorize_url():

    params = {

        "client_id":
            GOOGLE_CLIENT_ID,

        "redirect_uri":
            GOOGLE_REDIRECT_URI,

        "response_type":
            "code",

        "scope":
            "openid email profile",

        "access_type":
            "offline",

        "prompt":
            "select_account"

    }

    return (
        "https://accounts.google.com/"
        "o/oauth2/v2/auth?"
        + urllib.parse.urlencode(params)
    )


def google_exchange_code(code):

    import requests

    token = requests.post(

        "https://oauth2.googleapis.com/token",

        data={

            "code":
                code,

            "client_id":
                GOOGLE_CLIENT_ID,

            "client_secret":
                GOOGLE_CLIENT_SECRET,

            "redirect_uri":
                GOOGLE_REDIRECT_URI,

            "grant_type":
                "authorization_code"

        },

        timeout=15

    )

    token.raise_for_status()

    access = token.json().get(
        "access_token"
    )

    if not access:

        raise ValueError(
            "Google did not return an access token"
        )

    profile = requests.get(

        "https://openidconnect.googleapis.com/v1/userinfo",

        headers={
            "Authorization":
                f"Bearer {access}"
        },

        timeout=15

    )

    profile.raise_for_status()

    return profile.json()


# ============================================================
# STORAGE
# ============================================================

UPLOAD_FOLDER = os.path.join(BASE_DIR, "logs")

EVIDENCE_FOLDER = os.path.join(
    UPLOAD_FOLDER,
    "evidence"
)

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

os.makedirs(
    EVIDENCE_FOLDER,
    exist_ok=True
)


DB_PATH = os.path.join(BASE_DIR, "users.db")


# ============================================================
# DATABASE
# ============================================================

def get_db():

    conn = sqlite3.connect(
        DB_PATH,
        timeout=10.0
    )

    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")

    return conn


def init_db():

    conn = get_db()

    cur = conn.cursor()

    # --------------------------------------------------------
    # USERS
    # --------------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    """)

    # --------------------------------------------------------
    # GOOGLE / OAUTH FIELDS
    # --------------------------------------------------------

    for column, definition in (

        # Keeps older users.db files compatible with the current app.
        ("role", "TEXT DEFAULT 'user'"),

        ("email", "TEXT"),

        ("google_id", "TEXT"),

        ("avatar", "TEXT")

    ):

        try:

            cur.execute(
                f"ALTER TABLE users ADD COLUMN "
                f"{column} {definition}"
            )

        except sqlite3.OperationalError:

            pass

    # --------------------------------------------------------
    # ACTIVITY LOGS
    # --------------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            action TEXT,
            time TEXT
        )
    """)

    # --------------------------------------------------------
    # THREAT LOGS
    # --------------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS threat_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            threat TEXT,
            severity TEXT,
            time TEXT
        )
    """)

    # --------------------------------------------------------
    # INCIDENTS
    # --------------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_code TEXT UNIQUE,
            title TEXT NOT NULL,
            description TEXT,
            incident_type TEXT,
            severity TEXT DEFAULT 'Medium',
            status TEXT DEFAULT 'OPEN',
            source_ip TEXT,
            target TEXT,
            reporter TEXT,
            assigned_to TEXT,
            created_at TEXT,
            updated_at TEXT,
            resolution TEXT
        )
    """)

    # --------------------------------------------------------
    # INCIDENT HISTORY
    # --------------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS incident_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            actor TEXT,
            action TEXT,
            details TEXT,
            created_at TEXT
        )
    """)

    # --------------------------------------------------------
    # INCIDENT EVIDENCE
    # --------------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS incident_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            evidence_type TEXT,
            description TEXT,
            file_name TEXT,
            sha256 TEXT,
            added_by TEXT,
            created_at TEXT
        )
    """)

    # --------------------------------------------------------
    # NOTIFICATIONS
    # --------------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            incident_id INTEGER,
            message TEXT,
            severity TEXT,
            created_at TEXT,
            is_read INTEGER DEFAULT 0
        )
    """)

    # --------------------------------------------------------
    # SCALABILITY INDEXES
    # --------------------------------------------------------

    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_google ON users(google_id);")

    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_code ON incidents(incident_code);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);")

    cur.execute("CREATE INDEX IF NOT EXISTS idx_history_incident_id ON incident_history(incident_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_evidence_incident_id ON incident_evidence(incident_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(username, is_read);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_logs_ip ON threat_logs(ip);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_activity_logs_time ON activity_logs(time);")

    # --------------------------------------------------------
    # SECURE ADMIN SEEDING & PASSWORD HASH UPGRADE
    # --------------------------------------------------------

    cur.execute("SELECT id, role, password FROM users WHERE LOWER(username) = 'kunal sharma'")
    admin_row = cur.fetchone()
    if not admin_row:
        cur.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("kunal sharma", generate_password_hash("sharma@123"), "admin")
        )
    else:
        cur.execute(
            "UPDATE users SET role = 'admin', password = ? WHERE LOWER(username) = 'kunal sharma'",
            (generate_password_hash("sharma@123"),)
        )

    # Migrate any legacy plaintext passwords to secure hashes
    cur.execute("SELECT id, password FROM users")
    for u in cur.fetchall():
        pwd = u["password"]
        if pwd and not (pwd.startswith("scrypt:") or pwd.startswith("pbkdf2:")):
            cur.execute("UPDATE users SET password = ? WHERE id = ?", (generate_password_hash(pwd), u["id"]))

    conn.commit()

    conn.close()


init_db()


# ============================================================
# LOGIN SECURITY & RATE LIMITING
# ============================================================

login_attempts = {}

lock_time = {}

MAX_ATTEMPTS = 5

LOCK_DURATION = 30

activity_log = []


def clean_rate_limits():
    """Prune expired lockouts and stale attempt counters to prevent memory leaks."""
    now_ts = time.time()
    expired = [ip for ip, expiry in lock_time.items() if now_ts >= expiry]
    for ip in expired:
        lock_time.pop(ip, None)
        login_attempts.pop(ip, None)


# ============================================================
# HELPERS
# ============================================================

def now():

    return datetime.datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def current_user():

    return session.get(
        "user",
        "Unknown"
    )


def log_activity(action):

    user = current_user()

    current_time = now()

    activity_log.append({

        "time":
            current_time,

        "action":
            action

    })

    conn = get_db()

    conn.execute(

        """
        INSERT INTO activity_logs
        (user, action, time)
        VALUES (?, ?, ?)
        """,

        (
            user,
            action,
            current_time
        )

    )

    conn.commit()

    conn.close()


def log_threat(
    ip,
    threat,
    severity
):

    conn = get_db()

    conn.execute(

        """
        INSERT INTO threat_logs
        (ip, threat, severity, time)
        VALUES (?, ?, ?, ?)
        """,

        (
            ip,
            threat,
            severity,
            now()
        )

    )

    conn.commit()

    conn.close()


def severity_normalize(value):

    value = str(
        value or "Medium"
    ).strip().title()

    allowed = {

        "Low",
        "Medium",
        "High",
        "Critical"

    }

    if value in allowed:

        return value

    return "Medium"


def create_notification(
    incident_id,
    severity,
    message
):

    conn = get_db()

    recipients = {
        current_user()
    }

    rows = conn.execute(

        """
        SELECT username
        FROM users
        WHERE role='admin'
        """

    ).fetchall()

    recipients.update(
        row[0]
        for row in rows
    )

    for username in recipients:

        conn.execute(

            """
            INSERT INTO notifications
            (
                username,
                incident_id,
                message,
                severity,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,

            (
                username,
                incident_id,
                message,
                severity,
                now()
            )

        )

    conn.commit()

    conn.close()


def add_history(
    incident_id,
    action,
    details=""
):

    conn = get_db()

    conn.execute(

        """
        INSERT INTO incident_history
        (
            incident_id,
            actor,
            action,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,

        (
            incident_id,
            current_user(),
            action,
            details,
            now()
        )

    )

    conn.commit()

    conn.close()


# ============================================================
# INCIDENT CREATION
# ============================================================

def create_incident(
    title,
    description,
    incident_type,
    severity="Medium",
    source_ip=None,
    target=None,
    assigned_to=None
):

    severity = severity_normalize(
        severity
    )

    timestamp = now()

    code = (
        "INC-"
        + datetime.datetime.now().strftime(
            "%Y%m%d"
        )
        + "-"
        + uuid.uuid4().hex[:6].upper()
    )

    conn = get_db()

    cur = conn.cursor()

    cur.execute(

        """
        INSERT INTO incidents
        (
            incident_code,
            title,
            description,
            incident_type,
            severity,
            status,
            source_ip,
            target,
            reporter,
            assigned_to,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,

        (
            code,
            title,
            description,
            incident_type,
            severity,
            "OPEN",
            source_ip,
            target,
            current_user(),
            assigned_to,
            timestamp,
            timestamp
        )

    )

    incident_id = cur.lastrowid

    conn.commit()

    conn.close()

    add_history(

        incident_id,

        "Incident Created",

        f"Severity: {severity}; "
        f"Type: {incident_type}"

    )

    create_notification(

        incident_id,

        severity,

        f"{severity.upper()} incident created: "
        f"{code} — {title}"

    )

    return incident_id


# ============================================================
# INCIDENT FETCH
# ============================================================

def get_incident(
    incident_id
):

    conn = get_db()

    incident = conn.execute(

        """
        SELECT *
        FROM incidents
        WHERE id=?
        """,

        (incident_id,)

    ).fetchone()

    history = conn.execute(

        """
        SELECT *
        FROM incident_history
        WHERE incident_id=?
        ORDER BY id DESC
        """,

        (incident_id,)

    ).fetchall()

    evidence = conn.execute(

        """
        SELECT *
        FROM incident_evidence
        WHERE incident_id=?
        ORDER BY id DESC
        """,

        (incident_id,)

    ).fetchall()

    conn.close()

    return (
        incident,
        history,
        evidence
    )


# ============================================================
# INCIDENT STATISTICS
# ============================================================

def get_incident_stats():

    conn = get_db()

    total = conn.execute(
        "SELECT COUNT(*) FROM incidents"
    ).fetchone()[0]

    open_count = conn.execute(

        """
        SELECT COUNT(*)
        FROM incidents
        WHERE status NOT IN
        ('RESOLVED','CLOSED')
        """

    ).fetchone()[0]

    critical = conn.execute(

        """
        SELECT COUNT(*)
        FROM incidents
        WHERE severity='Critical'
        AND status NOT IN
        ('RESOLVED','CLOSED')
        """

    ).fetchone()[0]

    high = conn.execute(

        """
        SELECT COUNT(*)
        FROM incidents
        WHERE severity='High'
        AND status NOT IN
        ('RESOLVED','CLOSED')
        """

    ).fetchone()[0]

    investigating = conn.execute(

        """
        SELECT COUNT(*)
        FROM incidents
        WHERE status='INVESTIGATING'
        """

    ).fetchone()[0]

    resolved = conn.execute(

        """
        SELECT COUNT(*)
        FROM incidents
        WHERE status IN
        ('RESOLVED','CLOSED')
        """

    ).fetchone()[0]

    recent = conn.execute(

        """
        SELECT *
        FROM incidents
        ORDER BY id DESC
        LIMIT 8
        """

    ).fetchall()

    conn.close()

    return {

        "total":
            total,

        "open":
            open_count,

        "critical":
            critical,

        "high":
            high,

        "investigating":
            investigating,

        "resolved":
            resolved,

        "recent":
            recent

    }


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/",
    methods=["GET", "POST"]
)
def login():

    clean_rate_limits()

    ip = (
        request.remote_addr
        or "unknown"
    )

    login_attempts.setdefault(
        ip,
        0
    )

    lock_time.setdefault(
        ip,
        0
    )

    if time.time() < lock_time[ip]:

        return render_template(
            "login.html",
            error=(
                "Too many attempts. "
                "Try later."
            ),
            google_enabled=
                google_configured()
        )

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        conn = get_db()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE LOWER(username)=LOWER(?)
            """,
            (name,)
        ).fetchone()

        authenticated = False
        if user:
            stored_pwd = user["password"]
            if stored_pwd and (stored_pwd.startswith("scrypt:") or stored_pwd.startswith("pbkdf2:")):
                authenticated = check_password_hash(stored_pwd, password)
            elif stored_pwd and stored_pwd == password:
                authenticated = True
                try:
                    conn.execute(
                        "UPDATE users SET password=? WHERE id=?",
                        (generate_password_hash(password), user["id"])
                    )
                    conn.commit()
                except Exception:
                    pass

        if authenticated:
            session["user"] = user["username"]
            session["role"] = user["role"] if user["role"] else "user"
            login_attempts[ip] = 0
            clean_rate_limits()
            conn.close()

            log_activity(
                f"{session['user']} login"
            )

            return redirect(
                "/dashboard"
            )
        else:
            conn.close()
            login_attempts[ip] += 1

            if (
                login_attempts[ip]
                >= MAX_ATTEMPTS
            ):

                lock_time[ip] = (
                    time.time()
                    + LOCK_DURATION
                )

                return render_template(
                    "login.html",
                    error=(
                        "Account locked "
                        "for 30 seconds"
                    ),
                    google_enabled=
                        google_configured()
                )

            return render_template(
                "login.html",
                error="Invalid login",
                google_enabled=
                    google_configured()
            )

    return render_template(
        "login.html",
        google_enabled=
            google_configured()
    )


# ============================================================
# GOOGLE LOGIN
# ============================================================

@app.route(
    "/auth/google"
)
def google_login():

    if not google_configured():

        return redirect(

            url_for(

                "login",

                google_error=(
                    "Google OAuth is not "
                    "configured yet. Add "
                    "GOOGLE_CLIENT_ID, "
                    "GOOGLE_CLIENT_SECRET "
                    "and "
                    "GOOGLE_REDIRECT_URI "
                    "to .env."
                )

            )

        )

    session["oauth_state"] = (
        uuid.uuid4().hex
    )

    return redirect(

        google_authorize_url()
        + "&state="
        + session["oauth_state"]

    )


@app.route(
    "/auth/google/callback"
)
def google_callback():

    if not google_configured():

        return redirect("/")

    state = request.args.get(
        "state",
        ""
    )

    if (
        not state
        or
        state
        != session.pop(
            "oauth_state",
            None
        )
    ):

        return redirect(

            url_for(

                "login",

                google_error=(
                    "Google sign-in "
                    "state validation failed."
                )

            )

        )

    try:

        profile = google_exchange_code(
            request.args.get(
                "code",
                ""
            )
        )

        google_id = profile.get(
            "sub"
        )

        email = (
            profile.get(
                "email"
            )
            or ""
        ).strip().lower()

        name = (
            profile.get(
                "name"
            )
            or
            email.split("@")[0]
        ).strip().lower()

        if (
            not google_id
            or
            not email
        ):

            raise ValueError(
                "Google account did not "
                "return a verified email"
            )

        conn = get_db()

        user = conn.execute(

            """
            SELECT *
            FROM users
            WHERE google_id=?
            OR email=?
            """,

            (
                google_id,
                email
            )

        ).fetchone()

        if not user:

            conn.execute(

                """
                INSERT INTO users
                (
                    username,
                    password,
                    role,
                    email,
                    google_id,
                    avatar
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,

                (
                    name,
                    generate_password_hash(
                        uuid.uuid4().hex
                    ),
                    "user",
                    email,
                    google_id,
                    profile.get(
                        "picture"
                    )
                )

            )

            conn.commit()

            user = conn.execute(

                """
                SELECT *
                FROM users
                WHERE google_id=?
                """,

                (google_id,)

            ).fetchone()

        else:

            conn.execute(

                """
                UPDATE users
                SET
                    google_id=?,
                    email=?,
                    avatar=?
                WHERE id=?
                """,

                (
                    google_id,
                    email,
                    profile.get(
                        "picture"
                    ),
                    user[0]
                )

            )

            conn.commit()

            user = conn.execute(

                """
                SELECT *
                FROM users
                WHERE id=?
                """,

                (user[0],)

            ).fetchone()

        conn.close()

        session["user"] = user[1]

        session["role"] = user[3]

        session["email"] = email

        log_activity(
            "Google OAuth login"
        )

        return redirect(
            "/dashboard"
        )

    except Exception as exc:

        return redirect(

            url_for(

                "login",

                google_error=(
                    "Google sign-in failed: "
                    + str(exc)[:160]
                )

            )

        )


# ============================================================
# SIGNUP
# ============================================================

@app.route(
    "/signup",
    methods=["GET", "POST"]
)
def signup():

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if not re.match(

            r'^(?=.*[A-Z])'
            r'(?=.*\d)'
            r'(?=.*[@$!%*?&])'
            r'.{8,}$',

            password

        ):

            return render_template(

                "signup.html",

                error=(
                    "Password must contain "
                    "uppercase, number, "
                    "special character "
                    "and 8 chars"
                ),

                google_enabled=
                    google_configured()

            )

        hashed = generate_password_hash(
            password
        )

        conn = get_db()

        try:

            conn.execute(

                """
                INSERT INTO users
                (username, password)
                VALUES (?, ?)
                """,

                (
                    name,
                    hashed
                )

            )

            conn.commit()

        except sqlite3.IntegrityError:

            conn.close()

            return render_template(

                "signup.html",

                error="User already exists",

                google_enabled=
                    google_configured()

            )

        conn.close()

        return redirect("/")

    return render_template(

        "signup.html",

        google_enabled=
            google_configured()

    )


# ============================================================
# ============================================================
# DASHBOARD
# ============================================================

@app.route(
    "/dashboard"
)
@login_required
def dashboard():

    stats = get_incident_stats()

    conn = get_db()

    notifications = conn.execute(

        """
        SELECT *
        FROM notifications
        WHERE username=?
        ORDER BY id DESC
        LIMIT 8
        """,

        (
            current_user(),
        )

    ).fetchall()

    conn.close()

    return render_template(

        "index.html",

        activity=
            activity_log[-10:],

        incident_stats=
            stats,

        notifications=
            notifications

    )


# ============================================================
# INCIDENT LIST
# ============================================================

@app.route(
    "/incidents"
)
@login_required
def incidents():

    status = request.args.get(
        "status",
        "ALL"
    )

    severity = request.args.get(
        "severity",
        "ALL"
    )

    query = (
        "SELECT * FROM incidents "
        "WHERE 1=1"
    )

    params = []

    if status != "ALL":

        query += " AND status=?"

        params.append(
            status
        )

    if severity != "ALL":

        query += " AND severity=?"

        params.append(
            severity.title()
        )

    query += " ORDER BY id DESC"

    conn = get_db()

    rows = conn.execute(
        query,
        params
    ).fetchall()

    analysts = conn.execute(

        """
        SELECT username
        FROM users
        ORDER BY username
        """

    ).fetchall()

    conn.close()

    return render_template(

        "incidents.html",

        incidents=rows,

        analysts=analysts,

        selected_status=
            status,

        selected_severity=
            severity

    )


# ============================================================
# CREATE INCIDENT
# ============================================================

@app.route(
    "/incident/create",
    methods=["GET", "POST"]
)
@login_required
def incident_create():

    if request.method == "POST":

        title = request.form.get(
            "title",
            "Untitled Incident"
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        incident_type = request.form.get(
            "incident_type",
            "Other"
        )

        severity = request.form.get(
            "severity",
            "Medium"
        )

        source_ip = request.form.get(
            "source_ip",
            ""
        ).strip()

        target = request.form.get(
            "target",
            ""
        ).strip()

        assigned_to = (
            request.form.get(
                "assigned_to",
                ""
            ).strip()
            or None
        )

        incident_id = create_incident(

            title,

            description,

            incident_type,

            severity,

            source_ip,

            target,

            assigned_to

        )

        log_activity(
            f"Created incident #{incident_id}"
        )

        return redirect(

            url_for(

                "incident_detail",

                incident_id=
                    incident_id

            )

        )

    conn = get_db()

    analysts = conn.execute(

        """
        SELECT username
        FROM users
        ORDER BY username
        """

    ).fetchall()

    conn.close()

    return render_template(

        "incident_create.html",

        analysts=analysts

    )


# ============================================================
# INCIDENT DETAIL
# ============================================================

@app.route(
    "/incident/<int:incident_id>"
)
@login_required
def incident_detail(
    incident_id
):

    incident, history, evidence = (
        get_incident(
            incident_id
        )
    )

    if not incident:

        return "Incident not found", 404

    conn = get_db()

    analysts = conn.execute(

        """
        SELECT username
        FROM users
        ORDER BY username
        """

    ).fetchall()

    conn.close()

    return render_template(

        "incident_detail.html",

        incident=incident,

        history=history,

        evidence=evidence,

        analysts=analysts

    )


# ============================================================
# INCIDENT UPDATE
# ============================================================

@app.route(
    "/incident/<int:incident_id>/update",
    methods=["POST"]
)
@login_required
def incident_update(
    incident_id
):

    incident, _, _ = get_incident(
        incident_id
    )

    if not incident:

        return "Incident not found", 404

    action = request.form.get(
        "action"
    )

    conn = get_db()

    if action == "status":

        new_status = request.form.get(
            "status",
            "OPEN"
        )

        allowed = {

            "OPEN",
            "ASSIGNED",
            "INVESTIGATING",
            "CONTAINED",
            "RESOLVED",
            "CLOSED"

        }

        if new_status not in allowed:

            new_status = "OPEN"

        resolution = (
            request.form.get(
                "resolution",
                ""
            ).strip()
            or incident[12]
        )

        conn.execute(

            """
            UPDATE incidents
            SET
                status=?,
                resolution=?,
                updated_at=?
            WHERE id=?
            """,

            (
                new_status,
                resolution,
                now(),
                incident_id
            )

        )

        conn.commit()

        conn.close()

        add_history(

            incident_id,

            "Status Changed",

            f"{incident['status']} "
            f"→ {new_status}"

        )

        create_notification(

            incident_id,

            incident[5],

            f"Incident "
            f"{incident['incident_code']} "
            f"status changed to "
            f"{new_status}"

        )

        log_activity(

            f"Updated incident "
            f"{incident['incident_code']} "
            f"status to {new_status}"

        )

    elif action == "assign":

        assigned_to = (
            request.form.get(
                "assigned_to",
                ""
            ).strip()
            or None
        )

        conn.execute(

            """
            UPDATE incidents
            SET
                assigned_to=?,
                status=?,
                updated_at=?
            WHERE id=?
            """,

            (
                assigned_to,

                (
                    "ASSIGNED"
                    if assigned_to
                    else incident[6]
                ),

                now(),

                incident_id

            )

        )

        conn.commit()

        conn.close()

        add_history(

            incident_id,

            "Assignment Updated",

            (
                "Assigned to: "
                + (
                    assigned_to
                    or "Unassigned"
                )
            )

        )

        create_notification(

            incident_id,

            incident[5],

            (
                f"Incident "
                f"{incident['incident_code']} "
                f"assigned to "
                f"{assigned_to or 'Unassigned'}"
            )

        )

        log_activity(

            f"Assigned incident "
            f"{incident['incident_code']}"

        )

    elif action == "note":

        note = request.form.get(
            "note",
            ""
        ).strip()

        if note:

            add_history(

                incident_id,

                "Investigation Note",

                note

            )

            conn.close()

            log_activity(

                f"Added investigation note "
                f"to {incident['incident_code']}"

            )

        else:

            conn.close()

    return redirect(

        url_for(

            "incident_detail",

            incident_id=
                incident_id

        )

    )


# ============================================================
# INCIDENT EVIDENCE
# ============================================================

@app.route(
    "/incident/<int:incident_id>/evidence",
    methods=["POST"]
)
@login_required
def incident_evidence(
    incident_id
):

    incident, _, _ = get_incident(
        incident_id
    )

    if not incident:

        return "Incident not found", 404

    evidence_type = request.form.get(
        "evidence_type",
        "Other"
    )

    description = request.form.get(
        "description",
        ""
    ).strip()

    upload = request.files.get(
        "file"
    )

    file_name = None

    sha256 = None

    if upload and upload.filename:

        if not is_allowed_file(upload.filename, "evidence"):
            return "File type not allowed for evidence upload", 400

        safe_name = secure_filename(
            upload.filename
        )

        file_name = (

            f"{incident['incident_code']}_"
            f"{uuid.uuid4().hex[:8]}_"
            f"{safe_name}"

        )

        path = os.path.join(
            EVIDENCE_FOLDER,
            file_name
        )

        upload.save(path)

        h = hashlib.sha256()

        with open(
            path,
            "rb"
        ) as f:

            for chunk in iter(
                lambda:
                    f.read(8192),
                b""
            ):

                h.update(chunk)

        sha256 = h.hexdigest()

    conn = get_db()

    conn.execute(

        """
        INSERT INTO incident_evidence
        (
            incident_id,
            evidence_type,
            description,
            file_name,
            sha256,
            added_by,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,

        (
            incident_id,
            evidence_type,
            description,
            file_name,
            sha256,
            current_user(),
            now()
        )

    )

    conn.execute(

        """
        UPDATE incidents
        SET updated_at=?
        WHERE id=?
        """,

        (
            now(),
            incident_id
        )

    )

    conn.commit()

    conn.close()

    add_history(

        incident_id,

        "Evidence Added",

        (
            f"Type: {evidence_type}; "
            f"File: "
            f"{file_name or 'Metadata only'}"
        )

    )

    log_activity(

        f"Added evidence to "
        f"{incident['incident_code']}"

    )

    return redirect(

        url_for(

            "incident_detail",

            incident_id=
                incident_id

        )

    )


# ============================================================
# INCIDENT REPORT
# ============================================================

@app.route(
    "/incident/<int:incident_id>/report"
)
@login_required
def incident_report(
    incident_id
):

    incident, history, evidence = (
        get_incident(
            incident_id
        )
    )

    if not incident:

        return "Incident not found", 404

    buffer = io.BytesIO()

    c = canvas.Canvas(
        buffer
    )

    y = 800

    c.setFont(
        "Helvetica-Bold",
        16
    )

    c.drawString(

        50,
        y,

        "P13 - Cyber Incident "
        "Investigation Report"

    )

    y -= 35

    c.setFont(
        "Helvetica",
        10
    )

    fields = [

        (
            "Incident ID",
            incident[1]
        ),

        (
            "Title",
            incident[2]
        ),

        (
            "Type",
            incident[4]
        ),

        (
            "Severity",
            incident[5]
        ),

        (
            "Status",
            incident[6]
        ),

        (
            "Source IP",
            incident[7]
            or "N/A"
        ),

        (
            "Target",
            incident[8]
            or "N/A"
        ),

        (
            "Reporter",
            incident[9]
            or "N/A"
        ),

        (
            "Assigned To",
            incident[10]
            or "Unassigned"
        ),

        (
            "Created",
            incident[11]
        )

    ]

    for key, value in fields:

        c.drawString(

            50,
            y,

            f"{key}: {value}"

        )

        y -= 18

    y -= 10

    c.drawString(
        50,
        y,
        "Description:"
    )

    y -= 16

    desc = (
        incident[3]
        or ""
    ).replace(
        "\n",
        " "
    )

    for chunk_start in range(
        0,
        len(desc),
        95
    ):

        c.drawString(

            60,
            y,

            desc[
                chunk_start:
                chunk_start + 95
            ]

        )

        y -= 14

        if y < 100:

            c.showPage()

            y = 800

    y -= 10

    c.setFont(
        "Helvetica-Bold",
        11
    )

    c.drawString(
        50,
        y,
        "Investigation Timeline"
    )

    y -= 18

    c.setFont(
        "Helvetica",
        9
    )

    for item in history[:20]:

        line = (

            f"{item[5]} | "
            f"{item[2]} | "
            f"{item[3]} "
            f"{item[4] or ''}"

        )

        c.drawString(
            55,
            y,
            line[:120]
        )

        y -= 13

        if y < 70:

            c.showPage()

            y = 800

    c.save()

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"{incident['incident_code']}_report.pdf",
        mimetype="application/pdf"
    )


# ============================================================
# ADMIN
# ============================================================

@app.route(
    "/admin"
)
@login_required
@admin_required
def admin():

    if session.get(
        "role"
    ) != "admin":

        return "Access Denied", 403

    conn = get_db()

    users = conn.execute(

        """
        SELECT username, role
        FROM users
        """

    ).fetchall()

    logs = conn.execute(

        """
        SELECT user, action, time
        FROM activity_logs
        ORDER BY id DESC
        LIMIT 20
        """

    ).fetchall()

    threats = conn.execute(

        """
        SELECT ip, threat, severity, time
        FROM threat_logs
        ORDER BY id DESC
        LIMIT 20
        """

    ).fetchall()

    incidents = conn.execute(

        """
        SELECT *
        FROM incidents
        ORDER BY id DESC
        LIMIT 20
        """

    ).fetchall()

    conn.close()

    return render_template(

        "admin.html",

        users=users,

        logs=logs,

        threats=threats,

        incidents=incidents

    )


# ============================================================
# LOG ANALYSIS
# ============================================================

@app.route(
    "/log",
    methods=["POST"]
)
@login_required
def log_route():

    file = request.files.get(
        "logfile"
    )

    if (
        not file
        or
        not file.filename
    ):

        return redirect(
            "/dashboard"
        )

    if not is_allowed_file(file.filename, "log"):
        return render_template(
            "result.html",
            title="Log Analysis Error",
            data={"error": "Invalid file extension. Allowed extensions: .log, .txt, .csv, .json"},
            summary={
                "Open Ports": 0,
                "Closed Ports": 0,
                "Total Alerts": 0,
                "Risk": "Low"
            },
            lat=20,
            lon=78,
            alert=True,
            incident_id=None
        ), 400

    filename = f"{uuid.uuid4().hex[:8]}_{secure_filename(file.filename)}"

    path = os.path.join(
        UPLOAD_FOLDER,
        filename
    )

    file.save(path)

    result = analyze_log(
        path
    )

    severity = (

        "Critical"

        if result["brute_force"] >= 10

        else "High"

        if (
            result["brute_force"] > 0
            or
            result["unauthorized"] > 0
        )

        else "Medium"

    )

    incident_id = create_incident(

        "Suspicious Log Activity",

        (
            "Uploaded log analyzed. "
            f"Brute-force events: "
            f"{result['brute_force']}; "
            f"Unauthorized events: "
            f"{result['unauthorized']}; "
            f"Suspicious IPs: "
            f"{len(result['suspicious_ips'])}."
        ),

        "Log Analysis",

        severity,

        request.remote_addr,

        "Log File"

    )

    log_activity(
        "Log analysis"
    )

    log_threat(

        request.remote_addr,

        "Suspicious Log Activity",

        severity.upper()

    )

    return render_template(

        "result.html",

        title="Log Analysis",

        data=result,

        summary={

            "Open Ports":
                0,

            "Closed Ports":
                0,

            "Total Alerts":
                result["brute_force"]
                + result["unauthorized"],

            "Risk":
                severity

        },

        lat=20,

        lon=78,

        alert=True,

        incident_id=
            incident_id

    )


# ============================================================
# NETWORK SCAN
# ============================================================

@app.route(
    "/network",
    methods=["POST"]
)
@login_required
def network():

    ip = request.form.get(
        "ip",
        ""
    ).strip()

    if not ip:
        return redirect("/dashboard")

    try:
        result = scan_ports(ip)
    except Exception as exc:
        return render_template(
            "result.html",
            title="Network Scan",
            data={"error": str(exc)},
            summary={
                "Open Ports": 0,
                "Closed Ports": 0,
                "Filtered Ports": 0,
                "Total Ports": 0,
                "Risk": "Low"
            },
            lat=20,
            lon=78,
            alert=True,
            incident_id=None
        )

    open_ports = [
        item for item in result
        if str(item.get("state", "")).upper() == "OPEN"
    ]

    closed_ports = [
        item for item in result
        if str(item.get("state", "")).upper() == "CLOSED"
    ]

    filtered_ports = [
        item for item in result
        if str(item.get("state", "")).upper() == "FILTERED"
    ]

    if len(open_ports) >= 4:
        severity = "High"
    elif len(open_ports) >= 2 or len(filtered_ports) >= 2:
        severity = "Medium"
    else:
        severity = "Low"

    incident_id = create_incident(
        "Network Port Scan",
        (
            f"TCP common-port scan performed against {ip}. "
            f"Open: {len(open_ports)}, "
            f"Filtered: {len(filtered_ports)}, "
            f"Closed: {len(closed_ports)}."
        ),
        "Network Reconnaissance",
        severity,
        request.remote_addr,
        ip
    )

    log_activity(
        f"Network scan completed for {ip}"
    )

    log_threat(
        ip,
        "Port Scanning",
        severity.upper()
    )

    return render_template(
        "result.html",
        title="Network Scan",
        data=result,
        summary={
            "Open Ports": len(open_ports),
            "Closed Ports": len(closed_ports),
            "Filtered Ports": len(filtered_ports),
            "Total Ports": len(result),
            "Risk": severity
        },
        lat=20,
        lon=78,
        alert=True,
        incident_id=incident_id
    )


# ============================================================
# INTEGRATED INCIDENT TRIAGE
# ============================================================

@app.route(
    "/triage",
    methods=["GET", "POST"]
)
@login_required
def triage():

    if request.method == "GET":
        return render_template("triage.html")

    target = request.form.get("target", "").strip()

    if not target:
        return render_template(
            "triage.html",
            error="Please enter an IP address or domain."
        )

    # ------------------------------------------------------------
    # Metasploitable2 authorized-lab profile
    # ------------------------------------------------------------
    target_lower = target.lower()
    lab_profile = None

    if target_lower in {
        "metasploitable2",
        "metasploitable",
        "metasploitable2.lab"
    }:
        lab_profile = "Metasploitable2"

    # Resolve target with SSRF protection.
    target_info = resolve_target(target)
    if not target_info.get("ok"):
        return render_template(
            "triage.html",
            error=target_info.get("error", "Unable to resolve or validate target"),
            target=target,
            lab_profile=lab_profile
        )
    resolved_ip = target_info["ip"]

    # ------------------------------------------------------------
    # Seven-port TCP scan
    # ------------------------------------------------------------
    try:
        scan_result = scan_ports(target)
    except Exception as exc:
        return render_template(
            "triage.html",
            error=f"Port scan failed: {exc}",
            target=target,
            resolved_ip=resolved_ip,
            lab_profile=lab_profile
        )

    open_ports = [
        item for item in scan_result
        if str(item.get("state", "")).upper() == "OPEN"
    ]

    closed_ports = [
        item for item in scan_result
        if str(item.get("state", "")).upper() == "CLOSED"
    ]

    filtered_ports = [
        item for item in scan_result
        if str(item.get("state", "")).upper() == "FILTERED"
    ]

    # ------------------------------------------------------------
    # Firewall assessment
    # ------------------------------------------------------------
    firewall_detected = bool(filtered_ports)

    if len(filtered_ports) >= 2:
        firewall_status = (
            "FILTERED — stateful firewall, ACL or network filtering "
            "is likely on one or more tested ports."
        )
    elif len(filtered_ports) == 1:
        firewall_status = (
            "PARTIAL FILTERING — possible firewall or ACL on the "
            "filtered service."
        )
    else:
        firewall_status = (
            "No filtering observed on the tested TCP ports. "
            "This does not prove that no firewall exists."
        )

    # ------------------------------------------------------------
    # Deterministic exposure score
    # ------------------------------------------------------------
    threat_score = min(
        100,
        (len(open_ports) * 8) + (len(filtered_ports) * 3)
    )

    sensitive_ports = {21, 23, 3306}

    for item in open_ports:
        try:
            port_number = int(item.get("port", 0))
        except (TypeError, ValueError):
            port_number = 0

        if port_number in sensitive_ports:
            threat_score += 15

    threat_score = min(threat_score, 100)

    if threat_score >= 70:
        risk_level = "CRITICAL"
    elif threat_score >= 45:
        risk_level = "HIGH"
    elif threat_score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # ------------------------------------------------------------
    # Metasploitable2 lab service / CVE reference flags
    # IMPORTANT: these are reference mappings. A TCP port alone does
    # not prove the exact software version. Verify with banner/version
    # enumeration inside the authorized lab before claiming a CVE.
    # ------------------------------------------------------------
    metasploitable_services = {
        21: {
            "service": "FTP",
            "reference": "vsftpd 2.3.4",
            "cve": "CVE-2011-2523",
            "note": "Known Metasploitable2 lab FTP backdoor reference; verify the banner/version."
        },
        22: {
            "service": "SSH",
            "reference": "SSH",
            "cve": "",
            "note": "SSH service observed; verify the exact implementation/version before vulnerability attribution."
        },
        23: {
            "service": "Telnet",
            "reference": "Telnet",
            "cve": "",
            "note": "Cleartext remote administration protocol; treat as an insecure legacy service in the lab."
        },
        80: {
            "service": "HTTP",
            "reference": "Apache HTTP",
            "cve": "",
            "note": "Web service reference for the Metasploitable2 lab; verify the exact server/version."
        }
    }

    lab_findings = []

    if lab_profile:
        for item in open_ports:
            try:
                port_number = int(item.get("port", 0))
            except (TypeError, ValueError):
                continue

            reference = metasploitable_services.get(port_number)
            if reference:
                finding = dict(reference)
                finding["port"] = port_number
                finding["state"] = "OPEN"
                lab_findings.append(finding)

    # ------------------------------------------------------------
    # Firewall analysis guidance
    # ------------------------------------------------------------
    firewall_guidance = []

    if filtered_ports:
        filtered_numbers = [
            str(item.get("port", "?"))
            for item in filtered_ports
        ]

        firewall_guidance.append(
            "Filtered ports detected: "
            + ", ".join(filtered_numbers)
            + ". Review host firewall, perimeter ACL and WAF rules."
        )

        firewall_guidance.append(
            "For an authorized lab, compare TCP connection behavior "
            "and firewall logs to distinguish CLOSED from FILTERED."
        )

        firewall_guidance.append(
            "ACK-based firewall mapping can be used in an isolated "
            "authorized lab to study whether filtering rules are present."
        )
    else:
        firewall_guidance.append(
            "No tested port was classified as FILTERED. This is not "
            "proof that the target has no firewall."
        )

    firewall_guidance.append(
        "Do not use fragmentation, decoys or other firewall-evasion "
        "techniques against systems you do not own or have explicit "
        "permission to test."
    )

    # ------------------------------------------------------------
    # Geo-IP enrichment
    # ------------------------------------------------------------
    geo = {
        "country": "Unavailable",
        "region": "Unavailable",
        "city": "Unavailable",
        "isp": "Unavailable"
    }

    try:
        geo_response = requests.get(
            f"http://ip-api.com/json/{resolved_ip}",
            params={
                "fields": "status,country,regionName,city,isp,query"
            },
            timeout=5
        )

        if geo_response.ok:
            geo_data = geo_response.json()

            if geo_data.get("status") == "success":
                geo = {
                    "country": geo_data.get("country", "Unavailable"),
                    "region": geo_data.get("regionName", "Unavailable"),
                    "city": geo_data.get("city", "Unavailable"),
                    "isp": geo_data.get("isp", "Unavailable")
                }

    except Exception:
        pass

    # ------------------------------------------------------------
    # Analyst recommendations
    # ------------------------------------------------------------
    recommendations = []

    if open_ports:
        recommendations.append(
            "Review exposed services and confirm that each service is required."
        )

    if filtered_ports:
        recommendations.append(
            "Review firewall/ACL rules for the filtered services and compare the result with firewall logs."
        )

    if any(
        int(item.get("port", 0)) in sensitive_ports
        for item in open_ports
        if str(item.get("port", "")).isdigit()
    ):
        recommendations.append(
            "A sensitive service is exposed; verify authentication, access controls and network segmentation."
        )

    if lab_findings:
        recommendations.append(
            "Metasploitable2 lab references detected. Verify service banners/versions before assigning a CVE to the running service."
        )

    if not recommendations:
        recommendations.append(
            "No immediate high-risk exposure was identified in the tested common TCP ports."
        )

    incident_severity = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low"
    }.get(risk_level, "Low")

    incident_id = create_incident(
        "Integrated Incident Triage",
        (
            f"Full triage completed for {target} ({resolved_ip}). "
            f"Threat score: {threat_score}/100. Risk: {risk_level}. "
            f"Open: {len(open_ports)}, Filtered: {len(filtered_ports)}, "
            f"Closed: {len(closed_ports)}."
        ),
        "Incident Triage",
        incident_severity,
        resolved_ip,
        target
    )

    log_activity(f"Full triage executed for {target}")
    log_threat(resolved_ip, "Integrated Triage", risk_level)

    return render_template(
        "triage.html",
        target=target,
        resolved_ip=resolved_ip,
        scan_result=scan_result,
        open_count=len(open_ports),
        closed_count=len(closed_ports),
        filtered_count=len(filtered_ports),
        total_count=len(scan_result),
        firewall_detected=firewall_detected,
        firewall_status=firewall_status,
        firewall_guidance=firewall_guidance,
        threat_score=threat_score,
        risk_level=risk_level,
        geo=geo,
        recommendations=recommendations,
        incident_id=incident_id,
        lab_profile=lab_profile,
        lab_findings=lab_findings
    )


# ============================================================
# PACKET ANALYSIS / PCAP
# ============================================================

@app.route(
    "/packet",
    methods=["POST"]
)
@login_required
def packet():

    file = request.files.get(
        "file"
    )

    if (
        file
        and
        file.filename
    ):

        if not is_allowed_file(file.filename, "packet"):
            return render_template(
                "result.html",
                title="Packet Analysis Error",
                data=["⚠ Error: Invalid packet file extension. Allowed extensions: .pcap, .pcapng, .cap, .log, .txt"],
                summary={
                    "Open Ports": 0,
                    "Closed Ports": 0,
                    "Total Alerts": 1,
                    "Risk": "Low"
                },
                lat=20,
                lon=78,
                alert=True,
                incident_id=None
            ), 400

        filename = f"{uuid.uuid4().hex[:8]}_{secure_filename(file.filename)}"

        path = os.path.join(
            UPLOAD_FOLDER,
            filename
        )

        file.save(path)

        result = analyze_packet_file(
            path
        )

        evidence_name = filename

    else:

        result = analyze_packet(

            request.form.get(
                "packet",
                ""
            )

        )

        evidence_name = (
            "Inline packet input"
        )

    alert_count = sum(

        1

        for x in result

        if "⚠" in x

    )

    severity = (

        "Critical"
        if alert_count >= 3

        else "High"
        if alert_count

        else "Medium"

    )

    incident_id = create_incident(

        "Suspicious Packet Analysis",

        (
            "Packet analysis completed. "
            f"{alert_count} threat pattern(s) "
            f"detected. Evidence: "
            f"{evidence_name}."
        ),

        "Packet Analysis",

        severity,

        request.remote_addr,

        "Packet Data"

    )

    log_activity(
        "Packet analysis"
    )

    log_threat(

        request.remote_addr,

        "Suspicious Packet",

        severity.upper()

    )

    return render_template(

        "result.html",

        title="Packet Analysis",

        data=result,

        summary={

            "Open Ports":
                0,

            "Closed Ports":
                0,

            "Total Alerts":
                alert_count,

            "Risk":
                severity

        },

        lat=20,

        lon=78,

        alert=True,

        incident_id=
            incident_id

    )


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

@app.route(
    "/threat",
    methods=["POST"]
)
@login_required
def threat():

    target_url = request.form.get(
        "url",
        ""
    ).strip()

    result = analyze_threat(
        target_url,
        scan_ports
    )

    if "error" in result:

        incident_id = create_incident(

            "Invalid Threat Intelligence Target",

            (
                "Threat check failed for "
                f"submitted URL: "
                f"{target_url}"
            ),

            "Threat Intelligence",

            "Low",

            request.remote_addr,

            target_url

        )

        data = result["data"]

    else:

        severity = (

            "High"

            if result[
                "summary"
            ].get("Risk") == "High"

            else "Medium"

        )

        incident_id = create_incident(

            "Threat Intelligence Match",

            (
                "Threat intelligence check "
                f"completed for {target_url}; "
                f"resolved IP: "
                f"{result.get('ip', 'N/A')}."
            ),

            "Threat Intelligence",

            severity,

            result.get("ip"),

            target_url

        )

        data = result["data"]

    log_activity(
        "Threat check"
    )

    log_threat(

        request.remote_addr,

        "Threat Intelligence Match",

        "HIGH"

    )

    return render_template(

        "result.html",

        title="Threat Detection",

        data=data,

        summary=result["summary"],

        lat=result["lat"],

        lon=result["lon"],

        alert=True,

        incident_id=
            incident_id

    )


# ============================================================
# LIVE PACKET MONITOR
# ============================================================

@app.route(
    "/live"
)
@login_required
def live():

    return render_template(

        "live.html",

        interfaces=
            live_interfaces(),

        capture_status=
            live_status()

    )


# ------------------------------------------------------------
# START LIVE CAPTURE
# ------------------------------------------------------------

@app.route(
    "/api/live/start",
    methods=["POST"]
)
@login_required
def api_live_start():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    interface = data.get(
        "interface"
    )

    result = start_capture(
        interface
    )

    if result.get("ok"):

        log_activity(

            "Live packet capture "
            f"started "
            f"({result.get('interface') or 'default interface'})"

        )

    return jsonify(
        result
    )


# ------------------------------------------------------------
# STOP LIVE CAPTURE
# ------------------------------------------------------------

@app.route(
    "/api/live/stop",
    methods=["POST"]
)
@login_required
def api_live_stop():

    result = stop_capture()

    log_activity(
        "Live packet capture stopped"
    )

    return jsonify(
        result
    )


# ------------------------------------------------------------
# LIVE CAPTURE STATUS
# ------------------------------------------------------------

@app.route(
    "/api/live/status"
)
@login_required
def api_live_status():

    return jsonify(
        live_status()
    )


# ------------------------------------------------------------
# LIVE PACKETS
# ------------------------------------------------------------

@app.route(
    "/api/live/packets"
)
@login_required
def api_live_packets():

    packets = get_packets(

        request.args.get(
            "limit",
            300
        ),

        request.args.get(
            "protocol",
            "ALL"
        ),

        request.args.get(
            "q",
            ""
        )

    )

    stats = {

        "total":
            len(packets),

        "tcp":
            sum(
                p.get(
                    "protocol"
                ) == "TCP"
                for p in packets
            ),

        "udp":
            sum(
                p.get(
                    "protocol"
                ) == "UDP"
                for p in packets
            ),

        "icmp":
            sum(
                p.get(
                    "protocol"
                ) == "ICMP"
                for p in packets
            ),

        "arp":
            sum(
                p.get(
                    "protocol"
                ) == "ARP"
                for p in packets
            ),

        "alerts":
            sum(
                p.get(
                    "risk"
                ) != "NORMAL"
                for p in packets
            )

    }

    return jsonify({

        "packets":
            packets,

        "stats":
            stats,

        "status":
            live_status()

    })


# ------------------------------------------------------------
# SINGLE LIVE PACKET
# ------------------------------------------------------------

@app.route(
    "/api/live/packet/<int:packet_id>"
)
@login_required
def api_live_packet(
    packet_id
):

    packet = get_packet(
        packet_id
    )

    if not packet:

        return jsonify({

            "error":
                "Packet not found"

        }), 404

    return jsonify(
        packet
    )


# ------------------------------------------------------------
# CLEAR LIVE PACKET BUFFER
# ------------------------------------------------------------

@app.route(
    "/api/live/clear",
    methods=["POST"]
)
@login_required
def api_live_clear():

    result = clear_packets()

    log_activity(
        "Live packet buffer cleared"
    )

    return jsonify(
        result
    )


# ------------------------------------------------------------
# PROMOTE LIVE PACKET TO P13 INCIDENT
# ------------------------------------------------------------

@app.route(
    "/api/live/promote",
    methods=["POST"]
)
@login_required
def api_live_promote():

    if "user" not in session:

        return jsonify({

            "ok":
                False,

            "error":
                "Authentication required"

        }), 401

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    packet_id = data.get(
        "packet_id"
    )

    packet = get_packet(
        packet_id
    )

    if not packet:

        return jsonify({

            "ok":
                False,

            "error":
                "Packet not found"

        }), 404

    severity = {

        "HIGH":
            "High",

        "MEDIUM":
            "Medium",

        "NORMAL":
            "Low"

    }.get(

        packet.get(
            "risk",
            "NORMAL"
        ),

        "Low"

    )

    incident_id = create_incident(

        "Live Packet Security Alert",

        (
            f"Live packet flagged as "
            f"{packet.get('risk')}. "
            f"{packet.get('info')}. "
            f"Source "
            f"{packet.get('src')} "
            f"→ "
            f"{packet.get('dst')}."
        ),

        "Live Packet Monitoring",

        severity,

        packet.get(
            "src"
        ),

        packet.get(
            "dst"
        )

    )

    add_history(

        incident_id,

        "Live Packet Evidence",

        (
            f"Packet #{packet.get('id')} • "
            f"{packet.get('protocol')} • "
            f"{packet.get('length')} bytes • "
            f"{packet.get('risk')}"
        )

    )

    log_activity(

        f"Promoted live packet "
        f"#{packet.get('id')} "
        f"to incident "
        f"#{incident_id}"

    )

    return jsonify({

        "ok":
            True,

        "incident_id":
            incident_id,

        "url":
            url_for(
                "incident_detail",
                incident_id=
                    incident_id
            )

    })


# ============================================================
# ATTACK SIMULATION
# ============================================================

@app.route(
    "/simulate/<attack>"
)
@login_required
def simulate_attack(
    attack
):

    data = {

        "Attack":
            attack.upper(),

        "Status":
            "Simulated Successfully",

        "Severity":
            "HIGH"

    }

    summary = {

        "Open Ports":
            5,

        "Closed Ports":
            2,

        "Total Alerts":
            7,

        "Risk":
            "HIGH"

    }

    incident_id = create_incident(

        f"Simulated "
        f"{attack.upper()} Attack",

        (
            "Controlled, "
            "non-destructive attack "
            "simulation executed for "
            "P13 workflow demonstration."
        ),

        "Attack Simulation",

        "Critical",

        request.remote_addr,

        "Simulation Lab"

    )

    log_activity(
        f"{attack} simulation"
    )

    log_threat(

        request.remote_addr,

        attack.upper(),

        "CRITICAL"

    )

    return render_template(

        "result.html",

        title="Attack Simulation",

        data=data,

        summary=summary,

        lat=20,

        lon=78,

        incident_id=
            incident_id

    )


# ============================================================
# AI ASSISTANT
# ============================================================

@app.route(
    "/ai_assistant"
)
@login_required
def ai_assistant():

    advice = [

        "Review open critical incidents first.",

        "Verify evidence integrity before closing an incident.",

        "Assign unowned high-severity incidents to an analyst.",

        "Review suspicious IP activity and related packet evidence.",

        "Update incident status and investigation notes after each response action."

    ]

    return {

        "status":
            "active",

        "recommendation":
            advice[
                int(time.time())
                % len(advice)
            ]

    }


# ============================================================
# PDF REPORT
# ============================================================

@app.route(
    "/download_report"
)
@login_required
def download_report():

    buffer = io.BytesIO()

    c = canvas.Canvas(
        buffer
    )

    c.drawString(

        100,
        800,

        "P13 Cyber Incident "
        "& Security Report"

    )

    c.drawString(

        100,
        760,

        f"Generated: "
        f"{datetime.datetime.now()}"

    )

    stats = get_incident_stats()

    c.drawString(

        100,
        720,

        f"Open Incidents: "
        f"{stats['open']}"

    )

    c.drawString(

        100,
        680,

        f"Critical Open Incidents: "
        f"{stats['critical']}"

    )

    c.drawString(

        100,
        640,

        "Cyber Incident Reporting "
        "& Triage Platform"

    )

    c.save()

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"p13_cyber_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
        mimetype="application/pdf"
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route(
    "/logout"
)
def logout():

    session.clear()

    return redirect("/")


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(error):

    if "user" in session:

        return render_template(
            "404.html"
        ), 404

    return "Page not found", 404


@app.errorhandler(500)
def internal_server_error(error):

    return (

        "Internal server error. "
        "Check the terminal for details."

    ), 500


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    host = os.getenv(
        "HOST",
        "0.0.0.0"
    )

    port = int(
        os.getenv(
            "PORT",
            "5000"
        )
    )

    app.run(

        host=host,

        port=port,

        debug=False

    )
