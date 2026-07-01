import os
import sqlite3
import json
import secrets
import hashlib
import smtplib
from email.message import EmailMessage
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, send_file, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from dotenv import load_dotenv
import re
from io import BytesIO
from cryptography.fernet import Fernet
import pyclamd
import tempfile
import subprocess
import requests
import hashlib
from datetime import datetime
from zoneinfo import ZoneInfo

from datetime import datetime, timezone, timedelta

UAE_TZ = timezone(timedelta(hours=4))

def to_dubai_time(db_time):
    if not db_time or db_time == "NULL":
        return "NULL"

    if isinstance(db_time, str):
        db_time = db_time.strip()
        dt_utc = datetime.fromisoformat(db_time)
    else:
        dt_utc = db_time

    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)

    dt_local = dt_utc.astimezone(UAE_TZ)
    return dt_local.strftime("%Y-%m-%d %H:%M:%S")
VT_API_KEY ="2d123dfb3efa67298c383c4848fdad85f59b89b34cb2c70b4e4fa879586d46b6"
def save_temp_file(file_data, original_name):
    os.makedirs("temp", exist_ok=True)
    ext = os.path.splitext(original_name)[1] or ".bin"
    temp_file = tempfile.NamedTemporaryFile(delete=False, dir="temp", suffix=ext)
    temp_file.write(file_data)
    temp_file.close()
    return temp_file.name

def vt_lookup_or_submit(file_path):
    try:
        headers = {"x-apikey": VT_API_KEY}

        with open(file_path, "rb") as f:
            file_bytes = f.read()

        sha256 = hashlib.sha256(file_bytes).hexdigest()

        # 1) Check if VT already knows this file by hash
        lookup = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=headers,
            timeout=30
        )

        if lookup.status_code == 200:
            data = lookup.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)

            return {
                "ok": True,
                "mode": "known",
                "status": "completed",
                "sha256": sha256,
                "malicious": malicious,
                "stats": stats
            }

        # 2) If not known, upload for analysis
        with open(file_path, "rb") as f:
            upload = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers=headers,
                files={"file": f},
                timeout=60
            )

        if upload.status_code not in (200, 201):
            print("VT upload failed:", upload.status_code, upload.text)
            return {"ok": False}

        up = upload.json()["data"]

        return {
            "ok": True,
            "mode": "submitted",
            "status": "queued",
            "analysis_id": up["id"],
            "sha256": sha256,
            "malicious": None,
            "stats": None
        }

    except Exception as e:
        print("VirusTotal error:", e)
        return {"ok": False}

def vt_check_analysis(analysis_id):
    headers = {"x-apikey": VT_API_KEY}
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers,
        timeout=30
    )

    if resp.status_code != 200:
        print("VT analysis fetch failed:", resp.status_code, resp.text)
        return None

    attrs = resp.json()["data"]["attributes"]
    status = attrs.get("status")
    stats = attrs.get("stats", {})
    malicious = stats.get("malicious", 0)

    return {
        "status": status,          # queued / in-progress / completed
        "malicious": malicious,
        "raw_stats": stats,
    }
    
def is_valid_email(email: str) -> bool:
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.match(pattern, email) is not None

load_dotenv()
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

fernet = Fernet(os.getenv("FILE_ENCRYPTION_KEY").encode())

def _mark_chat_as_read(chat_id, user_id=None, is_root=False):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COALESCE(MAX(id), 0) FROM chat_messages WHERE chat_id=?", (chat_id,))
    last_msg_id = cur.fetchone()[0] or 0

    if is_root:
        cur.execute("""
            INSERT INTO chat_reads (chat_id, user_id, is_root, last_read_message_id)
            VALUES (?, NULL, 1, ?)
            ON CONFLICT(chat_id, user_id, is_root)
            DO UPDATE SET last_read_message_id=excluded.last_read_message_id
        """, (chat_id, last_msg_id))
    else:
        cur.execute("""
            INSERT INTO chat_reads (chat_id, user_id, is_root, last_read_message_id)
            VALUES (?, ?, 0, ?)
            ON CONFLICT(chat_id, user_id, is_root)
            DO UPDATE SET last_read_message_id=excluded.last_read_message_id
        """, (chat_id, user_id, last_msg_id))

    conn.commit()
    conn.close()

def encrypt_file_bytes(data: bytes) -> bytes:
    return fernet.encrypt(data)

def decrypt_file_bytes(data: bytes) -> bytes:
    return fernet.decrypt(data)
DB_PATH = os.path.join(BASE_DIR, "database.db")
DATABASE = DB_PATH

# ---------------- OTP HELPERS ----------------
def generate_otp(length=6) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(length))

def hash_otp(otp: str, salt: str) -> str:
    return hashlib.sha256((salt + otp).encode("utf-8")).hexdigest()

def _safe_parse_dt(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    s = str(value)
    try:
        return datetime.fromisoformat(s)
    except Exception:
        pass
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def send_otp_email(to_email: str, otp: str) -> bool:
    """
    Sends OTP using Gmail SMTP with HTML design.
    Falls back to terminal OTP if SMTP fails.
    """

    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")

    if not smtp_user or not smtp_pass:
        print(f"[OTP] OTP for {to_email}: {otp}", flush=True)
        print("[OTP] SMTP not configured. Using terminal OTP.", flush=True)
        return False

    try:
        msg = EmailMessage()
        msg["Subject"] = "Your Secure Audit System OTP"
        msg["From"] = smtp_user
        msg["To"] = to_email

        # Plain fallback (important)
        msg.set_content(
            f"""Your OTP is: {otp}

This code expires in 10 minutes.

If you did not request this, ignore this email.
"""
        )

        # ✨ HTML Version (this is what makes it beautiful)
        msg.add_alternative(f"""
        <html>
        <body style="margin:0;padding:0;background:#0f172a;font-family:Arial,sans-serif;">
        
        <div style="max-width:520px;margin:40px auto;background:#111827;border-radius:20px;
                    overflow:hidden;border:1px solid rgba(255,255,255,0.08);">

            <div style="padding:26px;text-align:center;
                        background:linear-gradient(135deg,#5b5ffb,#8b5cf6);">
                <h2 style="margin:0;color:white;">Secure Audit System</h2>
                <p style="margin:6px 0 0;color:#e0e7ff;">Verification Code</p>
            </div>

            <div style="padding:30px;text-align:center;color:#d1d5db;">

                <p style="margin-bottom:16px;font-size:14px;">
                    Use this OTP to complete your verification:
                </p>

                <div style="
                    display:inline-block;
                    padding:16px 26px;
                    font-size:34px;
                    letter-spacing:6px;
                    font-weight:800;
                    color:#ffffff;
                    background:#1f2937;
                    border-radius:14px;
                    border:1px dashed #6366f1;">
                    {otp}
                </div>

                <p style="margin-top:20px;font-size:13px;color:#9ca3af;">
                    Expires in <b>10 minutes</b>
                </p>

                <p style="margin-top:20px;font-size:12px;color:#6b7280;">
                    If you didn't request this, ignore this email.
                </p>

            </div>

            <div style="text-align:center;padding:16px;font-size:11px;color:#6b7280;">
                © Secure Audit System
            </div>

        </div>

        </body>
        </html>
        """, subtype="html")

        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)

        print(f"[OTP] Email sent successfully to {to_email}", flush=True)
        return True

    except Exception as e:
        print(f"[SMTP ERROR] {e}", flush=True)
        print(f"[OTP FALLBACK] OTP for {to_email}: {otp}", flush=True)
        return False

# ---------------- DATABASE INIT + MIGRATIONS ----------------
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS companies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        company_name TEXT,
        company_username TEXT UNIQUE,
        company_password TEXT,
        company_email TEXT,
        description TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        role TEXT,
        company_id INTEGER
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        original_name TEXT,
        uploaded_by TEXT,
        assigned_to TEXT,
        staff_id INTEGER,
        company_id INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        role TEXT,
        action TEXT,
        staff_id INTEGER,
        company_id INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS public_transfers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT,
        filename TEXT,
        original_name TEXT,
        sha256 TEXT,
        uploader_ip TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        download_count INTEGER DEFAULT 0,
        max_downloads INTEGER DEFAULT 1,
        downloaded_at DATETIME
    )
    """)

    # Root/dev users (DB-based root)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS root_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # ---------------------------------------------------------
    # Chat system tables (single schema supports: company, admin_to_root, root_public)
    # ---------------------------------------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_type TEXT NOT NULL,              -- 'root_public' | 'company' | 'admin_to_root'
        company_id INTEGER,                   -- NULL for root_public/admin_to_root
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_by_user_id INTEGER,           -- NULL for visitor chats
        visitor_token TEXT,                   -- for root_public OR "low:high" for company OR "admin:<id>" for admin_to_root
        user1_id INTEGER,                     -- optional for company/admin_to_root pairing
        user2_id INTEGER                      -- optional for company/admin_to_root pairing
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        sender_type TEXT NOT NULL,            -- 'visitor' | 'user' | 'root'
        sender_user_id INTEGER,               -- NULL for visitor
        sender_name TEXT,
        message TEXT,
        file_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(chat_id) REFERENCES chats(id)
    )
    """)

    # ---------------------------------------------------------
    # Announcements (posted by root/developer)
    # ---------------------------------------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # ----- migrations (existing columns) -----
    cursor.execute("PRAGMA table_info(files)")
    files_cols = {row[1] for row in cursor.fetchall()}
    if "staff_id" not in files_cols:
        cursor.execute("ALTER TABLE files ADD COLUMN staff_id INTEGER")

    cursor.execute("PRAGMA table_info(audit_logs)")
    audit_cols = {row[1] for row in cursor.fetchall()}
    if "staff_id" not in audit_cols:
        cursor.execute("ALTER TABLE audit_logs ADD COLUMN staff_id INTEGER")

    cursor.execute("PRAGMA table_info(audit_logs)")
    audit_cols = {row[1] for row in cursor.fetchall()}
    audit_new_cols = {
        "actor_user_id": "INTEGER",
        "ip_address": "TEXT",
        "user_agent": "TEXT",
        "endpoint": "TEXT",
        "method": "TEXT",
        "status": "TEXT",
        "file_id": "INTEGER",
        "file_name": "TEXT",
        "target_user": "TEXT",
        "details": "TEXT"
    }
    for col, col_type in audit_new_cols.items():
        if col not in audit_cols:
            cursor.execute(f"ALTER TABLE audit_logs ADD COLUMN {col} {col_type}")

    cursor.execute("PRAGMA table_info(companies)")
    company_cols = {row[1] for row in cursor.fetchall()}
    company_new_cols = {
        "is_verified": "INTEGER DEFAULT 0",
        "otp_salt": "TEXT",
        "otp_hash": "TEXT",
        "otp_expires_at": "DATETIME",
        "otp_attempts": "INTEGER DEFAULT 0",
        "otp_last_sent_at": "DATETIME"
    }
    for col, col_type in company_new_cols.items():
        if col not in company_cols:
            cursor.execute(f"ALTER TABLE companies ADD COLUMN {col} {col_type}")

    # Chat migrations: add missing columns if your DB was created earlier without them
    cursor.execute("PRAGMA table_info(chats)")
    chats_cols = {row[1] for row in cursor.fetchall()}
    chats_new_cols = {
        "chat_type": "TEXT",
        "company_id": "INTEGER",
        "created_at": "DATETIME",
        "created_by_user_id": "INTEGER",
        "visitor_token": "TEXT",
        "user1_id": "INTEGER",
        "user2_id": "INTEGER",
    }
    for col, col_type in chats_new_cols.items():
        if col not in chats_cols:
            cursor.execute(f"ALTER TABLE chats ADD COLUMN {col} {col_type}")

    cursor.execute("PRAGMA table_info(chat_messages)")
    cm_cols = {row[1] for row in cursor.fetchall()}
    cm_new_cols = {
        "sender_type": "TEXT",
        "sender_user_id": "INTEGER",
        "sender_name": "TEXT",
        "message": "TEXT",
        "file_id": "INTEGER",
        "created_at": "DATETIME",
    }
    for col, col_type in cm_new_cols.items():
        if col not in cm_cols:
            cursor.execute(f"ALTER TABLE chat_messages ADD COLUMN {col} {col_type}")

    # Optionally seed a root user from environment on first run
    root_user = os.getenv("ROOT_USER")
    root_pass = os.getenv("ROOT_PASS")
    if root_user and root_pass:
        cursor.execute("SELECT 1 FROM root_users WHERE username=? LIMIT 1", (root_user,))
        if not cursor.fetchone():
            cursor.execute("INSERT INTO root_users (username, password_hash) VALUES (?,?)",
                           (root_user, generate_password_hash(root_pass)))

    conn.commit()
    conn.close()

# ---------------- Flask app ----------------
app = Flask(__name__)
app.secret_key = "supersecretkey"
app.permanent_session_lifetime = timedelta(hours=6)

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
PUBLIC_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, "public")
os.makedirs(PUBLIC_UPLOAD_FOLDER, exist_ok=True)

app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25MB
app.config["SESSION_REFRESH_EACH_REQUEST"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
def get_db():
    conn = sqlite3.connect(DATABASE)
    # safer row access if needed later:
    # conn.row_factory = sqlite3.Row
    return conn

# ---------------- Audit log helpers ----------------
def _get_client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr

def log_action(action, status="SUCCESS", file_id=None, file_name=None, target_user=None, details=None, company_id_override=None):
    """
    Writes a detailed audit log row. Should never crash the app.
    """
    if isinstance(details, dict):
        details = json.dumps(details, ensure_ascii=False)
    elif details is not None:
        details = str(details)

    actor_user_id = session.get("user_id")
    username = session.get("username") or "unknown"
    role = session.get("role") or "unknown"
    company_id = company_id_override if company_id_override is not None else session.get("company_id")

    ip_address = _get_client_ip()
    user_agent = request.headers.get("User-Agent", "")
    endpoint = request.path
    method = request.method

    staff_id = actor_user_id if role == "staff" else None

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO audit_logs (
                username, role, action, timestamp,
                staff_id, actor_user_id, company_id,
                ip_address, user_agent, endpoint, method,
                status, file_id, file_name, target_user, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            username, role, action, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            staff_id, actor_user_id, company_id,
            ip_address, user_agent, endpoint, method,
            status, file_id, file_name, target_user, details
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[AUDIT_LOG_ERROR] {e} | action={action} user={username} role={role}", flush=True)

def log_public(action, status="SUCCESS", file_name=None, details=None):
    # Public actions log as username/role = public
    try:
        conn = get_db()
        cur = conn.cursor()
        ip_address = _get_client_ip()
        user_agent = request.headers.get("User-Agent", "")
        endpoint = request.path
        method = request.method
        if isinstance(details, dict):
            details = json.dumps(details, ensure_ascii=False)
        elif details is not None:
            details = str(details)

        cur.execute("""
            INSERT INTO audit_logs (
                username, role, action, timestamp,
                staff_id, actor_user_id, company_id,
                ip_address, user_agent, endpoint, method,
                status, file_id, file_name, target_user, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "public", "public", action, datetime.now(),
            None, None, None,
            ip_address, user_agent, endpoint, method,
            status, None, file_name, None, details
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[AUDIT_LOG_ERROR] {e} | action={action} user=public role=public", flush=True)

def root_required():
    return bool(session.get("is_root") is True)

# =====================================================
#                ANNOUNCEMENTS (inject latest)
# =====================================================
@app.context_processor
def inject_latest_announcement():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, title, created_at FROM announcements ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        conn.close()
        if row:
            return {"latest_announcement": {"id": row[0], "title": row[1], "created_at": row[2]}}
    except Exception:
        pass
    return {"latest_announcement": None}



@app.route("/announcements")
def announcements_page():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, title, body, created_at FROM announcements ORDER BY id DESC LIMIT 200")
    items = cur.fetchall()
    conn.close()
    return render_template("announcements.html", items=items)

@app.route("/root/announcements", methods=["GET", "POST"])
def root_announcements():
    if not root_required():
        return redirect(url_for("root_login"))

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()[:120]
        body = (request.form.get("body") or "").strip()[:5000]
        if not title or not body:
            flash("Title and body required.", "danger")
        else:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("INSERT INTO announcements (title, body) VALUES (?,?)", (title, body))
            conn.commit()
            conn.close()
            flash("Announcement posted.", "success")
            log_action("ANNOUNCEMENT_POSTED", status="SUCCESS", details={"title": title}, company_id_override=None)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, title, body, created_at FROM announcements ORDER BY id DESC LIMIT 200")
    items = cur.fetchall()
    conn.close()
    return render_template("root_announcements.html", items=items)

# =====================================================
#                CHAT HELPERS (company + admin_to_root + root_public)
# =====================================================
def _get_or_create_pair_chat(chat_type: str, company_id, user_a: int, user_b: int) -> int:
    low, high = (user_a, user_b) if user_a < user_b else (user_b, user_a)
    token = f"{low}:{high}"

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id FROM chats
        WHERE chat_type=? AND company_id IS ? AND visitor_token=?
        ORDER BY id DESC LIMIT 1
    """, (chat_type, company_id, token))
    row = cur.fetchone()

    if row:
        chat_id = row[0]
    else:
        cur.execute("""
            INSERT INTO chats (chat_type, company_id, created_by_user_id, visitor_token, user1_id, user2_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (chat_type, company_id, session.get("user_id"), token, low, high))
        chat_id = cur.lastrowid
        conn.commit()

    conn.close()
    return chat_id

def _chat_user_in_company(user_id: int, company_id: int) -> bool:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE id=? AND company_id=? LIMIT 1", (user_id, company_id))
    ok = cur.fetchone() is not None
    conn.close()
    return ok

def _can_access_chat(chat_row, user_id: int, is_root: bool) -> bool:
    # chat_row: (chat_type, company_id, user1_id, user2_id, visitor_token)
    chat_type, company_id, u1, u2, token = chat_row
    if is_root:
        # root can view all chats
        return True
    if chat_type == "root_public":
        # public chat should be accessed via visitor token mechanism (not via logged-in users)
        return False
    # company/admin_to_root: must be participant
    return user_id in (u1, u2)

# Public (visitor) chat init / messages / send remain (below), but now chats table exists in init_db.
@app.route("/chat/users_with_unread")
def chat_users_with_unread():
    if not session.get("user_id") or not session.get("company_id"):
        return {"ok": False, "error": "login required"}, 401

    company_id = session.get("company_id")
    my_id = int(session.get("user_id"))
    role = session.get("role")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, username, role
        FROM users
        WHERE company_id=?
        ORDER BY role, username
    """, (company_id,))
    rows = cur.fetchall()

    users = []
    for r in rows:
        uid, uname, urole = r
        if uid == my_id:
            continue

        low, high = (my_id, uid) if my_id < uid else (uid, my_id)
        token = f"{low}:{high}"

        cur.execute("""
            SELECT id
            FROM chats
            WHERE chat_type='company' AND company_id=? AND visitor_token=?
            ORDER BY id DESC LIMIT 1
        """, (company_id, token))
        chat_row = cur.fetchone()

        unread = 0
        chat_id = None

        if chat_row:
            chat_id = chat_row[0]
            cur.execute("""
                SELECT COUNT(*)
                FROM chat_messages m
                LEFT JOIN chat_reads r
                  ON r.chat_id = m.chat_id AND r.user_id = ? AND r.is_root = 0
                WHERE m.chat_id = ?
                  AND COALESCE(m.sender_user_id, -1) != ?
                  AND m.id > COALESCE(r.last_read_message_id, 0)
            """, (my_id, chat_id, my_id))
            unread = cur.fetchone()[0] or 0

        users.append({
            "id": uid,
            "username": uname,
            "role": urole,
            "chat_id": chat_id,
            "unread": unread
        })

    if role == "admin":
        users.insert(0, {
            "id": -999,
            "username": "Developer",
            "role": "root",
            "chat_id": None,
            "unread": 0
        })

    conn.close()
    return {"ok": True, "users": users}

@app.route("/chat/users")
def chat_users():
    """
    Returns list of users the current logged-in user can chat with.
    - staff/it/admin: users within same company
    - admin: additionally sees "Developer" option (pseudo id = -999)
    """
    if not session.get("user_id") or not session.get("company_id"):
        return {"ok": False, "error": "login required"}, 401

    company_id = session.get("company_id")
    my_id = session.get("user_id")
    role = session.get("role")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, username, role
        FROM users
        WHERE company_id=?
        ORDER BY role, username
    """, (company_id,))
    rows = cur.fetchall()
    conn.close()

    users = [{"id": r[0], "username": r[1], "role": r[2]} for r in rows if r[0] != my_id]

    if role == "admin":
        # pseudo user for developer/root chat
        users.insert(0, {"id": -999, "username": "Developer", "role": "root"})

    return {"ok": True, "users": users}
@app.route("/root/chat/<int:chat_id>/send", methods=["POST"])
def root_chat_send(chat_id):
    if not root_required():
        return {"ok": False, "error": "root login required"}, 401

    data = request.json or {}
    msg = (data.get("message") or "").strip()
    if not msg:
        return {"ok": False, "error": "empty"}, 400
    msg = msg[:2000]

    sender_name = session.get("root_username") or "Developer"

    conn = get_db()
    cur = conn.cursor()

    # make sure chat exists
    cur.execute("SELECT id FROM chats WHERE id=? LIMIT 1", (chat_id,))
    if not cur.fetchone():
        conn.close()
        return {"ok": False, "error": "chat not found"}, 404

    # root can send to any chat (by design in your _can_access_chat)
    cur.execute("""
        INSERT INTO chat_messages (chat_id, sender_type, sender_user_id, sender_name, message)
        VALUES (?, 'root', NULL, ?, ?)
    """, (chat_id, sender_name, msg))

    conn.commit()
    conn.close()

    try:
        log_action("CHAT_MESSAGE", status="SUCCESS", details={"chat_id": chat_id, "sender_type": "root"}, company_id_override=None)
    except Exception:
        pass

    return {"ok": True}
@app.route("/chat/thread/start", methods=["POST"])
def chat_thread_start():
    """
    Start/open a chat thread:
    - company chat: between two users in same company
    - admin_to_root: admin chatting with root (pseudo id = -999)
    """
    if not session.get("user_id"):
        return {"ok": False, "error": "login required"}, 401

    data = request.json or {}
    target_id = int(data.get("target_id") or 0)
    if not target_id:
        return {"ok": False, "error": "missing target"}, 400

    my_id = int(session["user_id"])
    role = session.get("role")
    company_id = session.get("company_id")

    if target_id == -999:
        if role != "admin":
            return {"ok": False, "error": "not allowed"}, 403
        # admin_to_root uses company_id NULL; pairing admin user_id with 0 sentinel
        chat_id = _get_or_create_pair_chat("admin_to_root", None, my_id, 0)
        return {"ok": True, "chat_id": chat_id}

    # company chat: verify same company
    if not company_id or not _chat_user_in_company(target_id, company_id):
        return {"ok": False, "error": "invalid target"}, 403

    chat_id = _get_or_create_pair_chat("company", company_id, my_id, target_id)
    return {"ok": True, "chat_id": chat_id}

@app.route("/chat/thread/<int:chat_id>/messages")
def chat_thread_messages(chat_id):
    if not session.get("user_id") and not root_required():
        return {"ok": False, "error": "login required"}, 401

    since_id = int(request.args.get("since_id", "0"))
    my_id = session.get("user_id")
    is_root = root_required()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT chat_type, company_id, COALESCE(user1_id,0), COALESCE(user2_id,0), COALESCE(visitor_token,'')
        FROM chats
        WHERE id=?
    """, (chat_id,))
    chat_row = cur.fetchone()

    if not chat_row:
        conn.close()
        return {"ok": False, "error": "chat not found"}, 404

    if not _can_access_chat(chat_row, int(my_id or 0), is_root):
        conn.close()
        return {"ok": False, "error": "denied"}, 403

    cur.execute("""
        SELECT id, COALESCE(sender_user_id,0), COALESCE(sender_name,'Unknown'), COALESCE(message,''), created_at
        FROM chat_messages
        WHERE chat_id=? AND id>?
        ORDER BY id ASC
    """, (chat_id, since_id))
    rows = cur.fetchall()
    conn.close()

    _mark_chat_as_read(chat_id, my_id, is_root)

    msgs = [
        {
            "id": r[0],
            "sender_id": r[1],
            "sender": r[2],
            "message": r[3],
            "time": to_dubai_time(r[4])
        }
        for r in rows
    ]
    return {"ok": True, "messages": msgs}


@app.route("/chat/thread/<int:chat_id>/send", methods=["POST"])
def chat_thread_send(chat_id):
    if not session.get("user_id") and not root_required():
        return {"ok": False, "error": "login required"}, 401

    data = request.json or {}
    msg = (data.get("message") or "").strip()
    if not msg:
        return {"ok": False, "error": "empty"}, 400
    msg = msg[:2000]

    my_id = session.get("user_id")
    is_root = root_required()
    sender_name = session.get("username") or (session.get("root_username") if is_root else "Unknown")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT chat_type, company_id, COALESCE(user1_id,0), COALESCE(user2_id,0), COALESCE(visitor_token,'') FROM chats WHERE id=?", (chat_id,))
    chat_row = cur.fetchone()
    if not chat_row:
        conn.close()
        return {"ok": False, "error": "chat not found"}, 404

    if not _can_access_chat(chat_row, int(my_id or 0), is_root):
        conn.close()
        return {"ok": False, "error": "denied"}, 403

    sender_type = "root" if is_root else "user"
    cur.execute("""
        INSERT INTO chat_messages (chat_id, sender_type, sender_user_id, sender_name, message)
        VALUES (?, ?, ?, ?, ?)
    """, (chat_id, sender_type, my_id if not is_root else None, sender_name, msg))
    conn.commit()
    conn.close()

    try:
        log_action("CHAT_MESSAGE", status="SUCCESS", details={"chat_id": chat_id, "sender_type": sender_type}, company_id_override=None)
    except Exception:
        pass

    return {"ok": True}

# Root view of chats (simple)
@app.route("/root/chats")
def root_chats():
    if not root_required():
        return redirect(url_for("root_login"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            c.id,
            c.chat_type,
            COALESCE(comp.company_name, 'Unknown') AS company_name,
            COALESCE(u.username, 'Unknown') AS admin_username,
            COALESCE((
                SELECT m.created_at
                FROM chat_messages m
                WHERE m.chat_id = c.id
                ORDER BY m.id DESC
                LIMIT 1
            ), c.created_at) AS last_msg_at
        FROM chats c
        LEFT JOIN users u
          ON u.id = CASE
              WHEN c.chat_type='admin_to_root' THEN
                CASE
                  WHEN COALESCE(c.user1_id,0) > COALESCE(c.user2_id,0) THEN COALESCE(c.user1_id,0)
                  ELSE COALESCE(c.user2_id,0)
                END
              ELSE c.created_by_user_id
          END
        LEFT JOIN companies comp ON comp.id = u.company_id
        ORDER BY last_msg_at DESC
        LIMIT 200
    """)

    chats = cur.fetchall()
    conn.close()
    return render_template("root_chats.html", chats=chats)

@app.route("/root/chat/<int:chat_id>")
def root_chat_view(chat_id):
    if not root_required():
        return redirect(url_for("root_login"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            c.id,
            c.chat_type,
            COALESCE(comp.company_name, 'Unknown') AS company_name,
            COALESCE(u.username, 'Unknown') AS admin_username
        FROM chats c
        LEFT JOIN users u
          ON u.id = CASE
              WHEN c.chat_type='admin_to_root' THEN
                CASE
                  WHEN COALESCE(c.user1_id,0) > COALESCE(c.user2_id,0) THEN COALESCE(c.user1_id,0)
                  ELSE COALESCE(c.user2_id,0)
                END
              ELSE c.created_by_user_id
          END
        LEFT JOIN companies comp ON comp.id = u.company_id
        WHERE c.id=?
        LIMIT 1
    """, (chat_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        flash("Chat not found.", "danger")
        return redirect(url_for("root_chats"))

    return render_template(
        "root_chat_view.html",
        chat_id=chat_id,
        chat_type=row[1],
        company_name=row[2],
        admin_username=row[3]
    )

@app.route('/root/chat_unread_count')
def root_chat_unread_count():
    if not session.get('is_root'):
        return jsonify({"ok": False, "count": 0})

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM chats
        WHERE chat_type = 'admin_to_root'
    """)
    count = cursor.fetchone()[0]

    conn.close()

    return jsonify({"ok": True, "count": count})

# =====================================================
#                PUBLIC / VISITOR CHAT (optional)
# =====================================================
@app.route("/chat/public/init", methods=["POST"])
def chat_public_init():
    token = (request.json or {}).get("visitor_token")
    if not token:
        return {"ok": False, "error": "missing token"}, 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
      SELECT id FROM chats
      WHERE chat_type='root_public' AND visitor_token=?
      ORDER BY id DESC LIMIT 1
    """, (token,))
    row = cur.fetchone()

    if row:
        chat_id = row[0]
    else:
        cur.execute("""
          INSERT INTO chats (chat_type, company_id, created_by_user_id, visitor_token)
          VALUES ('root_public', NULL, NULL, ?)
        """, (token,))
        chat_id = cur.lastrowid
        conn.commit()

    conn.close()
    return {"ok": True, "chat_id": chat_id}

@app.route("/chat/<int:chat_id>/messages", methods=["GET"])
def chat_get_messages(chat_id):
    since_id = int(request.args.get("since_id", "0"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
      SELECT id, sender_type, COALESCE(sender_name,'Unknown'), COALESCE(message,''), created_at
      FROM chat_messages
      WHERE chat_id=? AND id>?
      ORDER BY id ASC
    """, (chat_id, since_id))
    rows = cur.fetchall()
    conn.close()

    msgs = [{
        "id": r[0],
        "sender_type": r[1],
        "sender_name": r[2],
        "message": r[3],
        "created_at": r[4],
    } for r in rows]

    return {"ok": True, "messages": msgs}

@app.route("/chat/<int:chat_id>/send", methods=["POST"])
def chat_send_message(chat_id):
    data = request.json or {}
    msg = (data.get("message") or "").strip()
    sender_type = data.get("sender_type")  # 'visitor' or 'user' or 'root'
    sender_name = (data.get("sender_name") or "Anonymous").strip()[:40]

    if not msg:
        return {"ok": False, "error": "empty"}, 400
    msg = msg[:2000]

    sender_user_id = session.get("user_id") if sender_type in ("user", "root") else None
    if sender_type in ("user", "root") and not session.get("user_id") and not root_required():
        return {"ok": False, "error": "not logged in"}, 401

    # Ensure chat exists
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT chat_type FROM chats WHERE id=? LIMIT 1", (chat_id,))
    exists = cur.fetchone()
    if not exists:
        conn.close()
        return {"ok": False, "error": "chat not found"}, 404

    cur.execute("""
      INSERT INTO chat_messages (chat_id, sender_type, sender_user_id, sender_name, message)
      VALUES (?, ?, ?, ?, ?)
    """, (chat_id, sender_type, sender_user_id, sender_name, msg))
    conn.commit()
    conn.close()

    try:
        log_action("CHAT_MESSAGE", status="SUCCESS", details={"chat_id": chat_id, "sender_type": sender_type}, company_id_override=None)
    except Exception:
        pass

    return {"ok": True}

# ---------------- Homepage ----------------
@app.route("/", methods=["GET"])
def home():
    return render_template("home.html")

# =====================================================
#                ROOT / DEVELOPER PORTAL
# =====================================================
@app.route("/root_login", methods=["GET", "POST"])
def root_login():
    """
    Root login supports:
      1) DB-based root_users table (preferred)
      2) Env ROOT_USER / ROOT_PASS as a fallback seed and auth
    """
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        # Check DB root user
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM root_users WHERE username=? LIMIT 1", (username,))
        row = cur.fetchone()
        conn.close()

        ok = False
        if row and check_password_hash(row[0], password):
            ok = True
        else:
            # Env fallback
            env_user = os.getenv("ROOT_USER")
            env_pass = os.getenv("ROOT_PASS")
            if env_user and env_pass and username == env_user and password == env_pass:
                ok = True

        if ok:
            session.clear()
            session["is_root"] = True
            session["root_username"] = username
            session.permanent = True
            log_action("ROOT_LOGIN", status="SUCCESS", details={"root_user": username}, company_id_override=None)
            return redirect(url_for("root_dashboard"))
        else:
            flash("Invalid root credentials.", "danger")
            log_action("ROOT_LOGIN", status="FAIL", details={"root_user": username}, company_id_override=None)

    return render_template("root_login.html")

@app.route("/root_logout")
def root_logout():
    if session.get("is_root"):
        log_action("ROOT_LOGOUT", status="SUCCESS", details={"root_user": session.get("root_username")}, company_id_override=None)
    session.clear()
    return redirect(url_for("home"))

@app.route("/root")
def root_dashboard():
    if not root_required():
        return redirect(url_for("root_login"))

    conn = get_db()
    cur = conn.cursor()

    # Companies list
    cur.execute("""
        SELECT id, company_name, company_username, company_email, COALESCE(is_verified,0)
        FROM companies
        ORDER BY id DESC
    """)
    companies = cur.fetchall()

    # Global stats
    cur.execute("SELECT COUNT(*) FROM companies")
    total_companies = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM audit_logs
        WHERE action='FILE_DOWNLOAD' AND COALESCE(status,'')='SUCCESS'
    """)
    total_enterprise_downloads = cur.fetchone()[0]

    # Public stats
    cur.execute("SELECT COUNT(*) FROM public_transfers")
    total_public_sends = cur.fetchone()[0]

    cur.execute("SELECT COALESCE(SUM(download_count),0) FROM public_transfers")
    total_public_downloads = cur.fetchone()[0]

    cur.execute("""
        SELECT id, timestamp, username, role, action, COALESCE(status,'NULL'), COALESCE(company_id,'NULL'), COALESCE(details,'NULL')
        FROM audit_logs
        WHERE action IN (
            'COMPANY_REGISTER','OTP_SENT','OTP_VERIFY_SUCCESS','OTP_VERIFY_FAIL',
            'COMPANY_LOGIN','COMPANY_LOGIN_FAIL','ROOT_LOGIN','ROOT_LOGOUT','ANNOUNCEMENT_POSTED'
        )
        ORDER BY id DESC
        LIMIT 50
    """)
    important_logs = cur.fetchall()

    conn.close()

    stats = {
        "total_companies": total_companies,
        "total_users": total_users,
        "total_enterprise_downloads": total_enterprise_downloads,
        "total_public_sends": total_public_sends,
        "total_public_downloads": total_public_downloads,
    }

    return render_template("root_dashboard.html", companies=companies, stats=stats, important_logs=important_logs)

@app.route("/root/company/<int:company_id>")
def root_company_detail(company_id):
    if not root_required():
        return redirect(url_for("root_login"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, company_name, company_username, company_email, description, COALESCE(is_verified,0)
        FROM companies
        WHERE id=?
    """, (company_id,))
    company = cur.fetchone()
    if not company:
        conn.close()
        flash("Company not found.", "danger")
        return redirect(url_for("root_dashboard"))

    cur.execute("""
        SELECT id, username, role
        FROM users
        WHERE company_id=?
        ORDER BY role, username
    """, (company_id,))
    users = cur.fetchall()

    cur.execute("SELECT COUNT(*) FROM files WHERE company_id=?", (company_id,))
    total_assigned_files = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM audit_logs
        WHERE company_id=? AND action='FILE_DOWNLOAD' AND COALESCE(status,'')='SUCCESS'
    """, (company_id,))
    downloads_success = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM audit_logs
        WHERE company_id=? AND action='FILE_DOWNLOAD' AND COALESCE(status,'')!='SUCCESS'
    """, (company_id,))
    downloads_denied_or_fail = cur.fetchone()[0]

    cur.execute("""
        SELECT id, timestamp, username, role, action, COALESCE(status,'NULL'), COALESCE(details,'NULL')
        FROM audit_logs
        WHERE company_id=?
          AND action IN ('COMPANY_REGISTER','OTP_SENT','OTP_VERIFY_SUCCESS','OTP_VERIFY_FAIL','COMPANY_LOGIN','COMPANY_LOGIN_FAIL')
        ORDER BY id DESC
        LIMIT 200
    """, (company_id,))
    company_events = cur.fetchall()

    cur.execute("""
        SELECT id, timestamp, COALESCE(status,'NULL'), COALESCE(username,'NULL'), COALESCE(role,'NULL'),
               COALESCE(ip_address,'NULL'), COALESCE(method,'NULL'), COALESCE(endpoint,'NULL'),
               COALESCE(action,'NULL'), COALESCE(file_name,'NULL'), COALESCE(target_user,'NULL'), COALESCE(details,'NULL')
        FROM audit_logs
        WHERE company_id=?
        ORDER BY id DESC
        LIMIT 300
    """, (company_id,))
    audit_rows = cur.fetchall()

    conn.close()

    metrics = {
        "total_assigned_files": total_assigned_files,
        "downloads_success": downloads_success,
        "downloads_denied_or_fail": downloads_denied_or_fail,
    }

    return render_template("root_company_detail.html",
                           company=company, users=users, metrics=metrics,
                           company_events=company_events, audit_rows=audit_rows)

@app.route("/root/audit")
def root_audit_all():
    if not root_required():
        return redirect(url_for("root_login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, timestamp, COALESCE(status,'NULL'), COALESCE(username,'NULL'), COALESCE(role,'NULL'),
               COALESCE(company_id,'NULL'), COALESCE(ip_address,'NULL'), COALESCE(method,'NULL'),
               COALESCE(endpoint,'NULL'), COALESCE(action,'NULL'), COALESCE(file_name,'NULL'), COALESCE(details,'NULL')
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 500
    """)
    rows = cur.fetchall()
    conn.close()
    return render_template("root_audit_all.html", rows=rows)
@app.route("/root/company/<int:company_id>/delete", methods=["POST"])
def root_delete_company(company_id):
    if not root_required():
        return redirect(url_for("root_login"))

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT company_name FROM companies WHERE id=? LIMIT 1", (company_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        flash("Company not found.", "danger")
        return redirect(url_for("root_dashboard"))

    company_name = row[0]

    # collect physical files first
    cur.execute("SELECT DISTINCT filename FROM files WHERE company_id=?", (company_id,))
    file_rows = cur.fetchall()

    try:
        # delete db data
        cur.execute("DELETE FROM chat_messages WHERE chat_id IN (SELECT id FROM chats WHERE company_id=?)", (company_id,))
        cur.execute("DELETE FROM chats WHERE company_id=?", (company_id,))
        cur.execute("DELETE FROM files WHERE company_id=?", (company_id,))
        cur.execute("DELETE FROM users WHERE company_id=?", (company_id,))
        cur.execute("DELETE FROM audit_logs WHERE company_id=?", (company_id,))
        cur.execute("DELETE FROM companies WHERE id=?", (company_id,))
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        flash(f"Could not delete company: {e}", "danger")
        return redirect(url_for("root_company_detail", company_id=company_id))

    conn.close()

    # optional: remove physical files from disk
    for f in file_rows:
        filename = f[0]
        if not filename:
            continue
        path = os.path.join(UPLOAD_FOLDER, filename)
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

    log_action(
        "ROOT_DELETE_COMPANY",
        status="SUCCESS",
        details={"deleted_company_id": company_id, "deleted_company_name": company_name},
        company_id_override=None
    )

    flash(f"Company deleted: {company_name}", "success")
    return redirect(url_for("root_dashboard"))

@app.route("/root/company/<int:company_id>/reset_admin", methods=["POST"])
def root_reset_admin(company_id):
    if not root_required():
        return redirect(url_for("root_login"))

    new_username = (request.form.get("admin_username") or "").strip()
    new_password = request.form.get("admin_password") or ""

    if not new_username or not new_password:
        flash("Admin username and password are required.", "danger")
        return redirect(url_for("root_company_detail", company_id=company_id))

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT company_name FROM companies WHERE id=? LIMIT 1", (company_id,))
    company = cur.fetchone()
    if not company:
        conn.close()
        flash("Company not found.", "danger")
        return redirect(url_for("root_dashboard"))

    cur.execute("""
        SELECT id, username
        FROM users
        WHERE company_id=? AND role='admin'
        ORDER BY id ASC
        LIMIT 1
    """, (company_id,))
    admin_row = cur.fetchone()

    if not admin_row:
        conn.close()
        flash("Admin user not found for this company.", "danger")
        return redirect(url_for("root_company_detail", company_id=company_id))

    admin_id, old_username = admin_row

    try:
        cur.execute("""
            UPDATE users
            SET username=?, password=?
            WHERE id=?
        """, (new_username, generate_password_hash(new_password), admin_id))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        flash("Username already exists. Choose another one.", "danger")
        return redirect(url_for("root_company_detail", company_id=company_id))

    conn.close()

    log_action(
        "ROOT_RESET_ADMIN_CREDENTIALS",
        status="SUCCESS",
        target_user=new_username,
        details={
            "company_id": company_id,
            "old_username": old_username,
            "new_username": new_username
        },
        company_id_override=None
    )

    flash("Admin credentials updated successfully.", "success")
    return redirect(url_for("root_company_detail", company_id=company_id))
# =====================================================
#                COMPANY LOGIN
# =====================================================
@app.route('/company_login', methods=['GET', 'POST'])
def company_login():
    if request.method == 'POST':
        company_username = request.form['company_username']
        company_password = request.form['company_password']

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, company_name, company_password, company_email, COALESCE(is_verified,0) "
            "FROM companies WHERE company_username=?",
            (company_username,))
        company = cursor.fetchone()
        conn.close()

        if company and check_password_hash(company[2], company_password):
            log_action("COMPANY_LOGIN", status="SUCCESS", details={"company_username": company_username}, company_id_override=company[0])

            if int(company[4]) != 1:
                session["pending_company_id"] = company[0]
                flash("Company not verified. Please verify OTP.", "warning")
                return redirect(url_for("verify_company_otp"))

            session['company_id'] = company[0]
            session['company_name'] = company[1]
            session['tab_session_key'] = secrets.token_hex(16)
            session['tab_bootstrap_pending'] = True
            session.permanent = True
            return redirect(url_for('portal_select'))
        else:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT id FROM companies WHERE company_username=? LIMIT 1", (company_username,))
            r = cur.fetchone()
            conn.close()
            cid = r[0] if r else None
            log_action("COMPANY_LOGIN_FAIL", status="FAIL", details={"company_username": company_username}, company_id_override=cid)
            flash("Invalid company credentials", "danger")

    return render_template("login.html")

# =====================================================
#                COMPANY REGISTRATION (WITH OTP)
# =====================================================
@app.route('/register_company', methods=['GET', 'POST'])
def register_company():
    if request.method == 'POST':
        company_name = request.form['company_name']
        company_email = (request.form['company_email'] or "").strip().lower()

        if not is_valid_email(company_email):
            flash("Please enter a valid email address.", "danger")
            return redirect(url_for('register_company'))
        description = request.form['description']
        company_username = request.form['company_username']
        company_password = generate_password_hash(request.form['company_password'])

        admin_username = request.form['admin_username']
        admin_password = generate_password_hash(request.form['admin_password'])

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT id, COALESCE(is_verified,0) FROM companies WHERE company_username=?", (company_username,))
        existing = cursor.fetchone()
        if existing:
            existing_id, is_verified = existing[0], int(existing[1] or 0)
            conn.close()
            if is_verified != 1:
                session["pending_company_id"] = existing_id
                flash("Company already registered but not verified. Please verify OTP.", "warning")
                return redirect(url_for("resend_company_otp"))
            flash("Company username already exists. Please choose another one.", "danger")
            return redirect(url_for('register_company'))

        try:
            cursor.execute("""
                INSERT INTO companies (company_name, company_email, description, company_username, company_password, is_verified)
                VALUES (?, ?, ?, ?, ?, 0)
            """, (company_name, company_email, description, company_username, company_password))
            company_id = cursor.lastrowid

            cursor.execute("""
                INSERT INTO users (username, password, role, company_id)
                VALUES (?, ?, 'admin', ?)
            """, (admin_username, admin_password, company_id))

            otp = generate_otp(6)
            salt = secrets.token_hex(16)
            otp_h = hash_otp(otp, salt)
            expires = datetime.now() + timedelta(minutes=10)

            cursor.execute("""
                UPDATE companies
                SET otp_salt = ?, otp_hash = ?, otp_expires_at = ?,
                    otp_attempts = 0, otp_last_sent_at = ?
                WHERE id = ?
            """, (salt, otp_h, expires, datetime.now(), company_id))

            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            conn.close()
            flash("Company username already exists. Please choose another one.", "danger")
            return redirect(url_for('register_company'))
        except Exception as e:
            conn.rollback()
            conn.close()
            flash(f"Registration failed: {e}", "danger")
            return redirect(url_for('register_company'))

        conn.close()

        log_action("COMPANY_REGISTER", status="SUCCESS",
                   details={"company_username": company_username, "company_email": company_email},
                   company_id_override=company_id)

        sent = send_otp_email(company_email, otp)
        session["pending_company_id"] = company_id

        if sent:
            log_action("OTP_SENT", status="SUCCESS", details={"to": company_email}, company_id_override=company_id)
            flash("Company registered. OTP sent to your email. Please verify.", "success")
        else:
            log_action("OTP_SENT", status="FAIL", details={"to": company_email, "note": "smtp_failed_demo_mode"}, company_id_override=company_id)
            flash("Company registered. OTP email could not be sent (SMTP). OTP shown in server terminal for demo.", "warning")

        return redirect(url_for("verify_company_otp"))

    return render_template("register_company.html")

# =====================================================
#                COMPANY OTP VERIFY
# =====================================================
@app.route("/verify_company_otp", methods=["GET", "POST"])
def verify_company_otp():
    pending_id = session.get("pending_company_id")
    if not pending_id:
        flash("No pending verification found. Please login or register.", "warning")
        return redirect(url_for("company_login"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT company_email, COALESCE(is_verified,0), otp_salt, otp_hash, otp_expires_at, COALESCE(otp_attempts,0)
        FROM companies
        WHERE id = ?
    """, (pending_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        session.pop("pending_company_id", None)
        flash("Company not found. Please register again.", "danger")
        return redirect(url_for("register_company"))

    company_email, is_verified, otp_salt, otp_hash_db, otp_expires_at, otp_attempts = row

    if int(is_verified) == 1:
        conn.close()
        session.pop("pending_company_id", None)
        flash("Company already verified. You can login now.", "success")
        return redirect(url_for("company_login"))

    if request.method == "POST":
        entered = (request.form.get("otp") or "").strip()

        if int(otp_attempts or 0) >= 5:
            conn.close()
            log_action("OTP_VERIFY_FAIL", status="DENIED", details={"reason": "too_many_attempts"}, company_id_override=pending_id)
            flash("Too many incorrect OTP attempts. Please request a new OTP.", "danger")
            return redirect(url_for("resend_company_otp"))

        exp_dt = _safe_parse_dt(otp_expires_at)
        if not exp_dt or datetime.now() > exp_dt:
            conn.close()
            log_action("OTP_VERIFY_FAIL", status="DENIED", details={"reason": "expired"}, company_id_override=pending_id)
            flash("OTP expired. Please request a new OTP.", "warning")
            return redirect(url_for("resend_company_otp"))

        if otp_salt and otp_hash_db and hash_otp(entered, otp_salt) == otp_hash_db:
            cursor.execute("""
                UPDATE companies
                SET is_verified = 1,
                    otp_salt = NULL,
                    otp_hash = NULL,
                    otp_expires_at = NULL,
                    otp_attempts = 0
                WHERE id = ?
            """, (pending_id,))
            conn.commit()
            conn.close()

            log_action("OTP_VERIFY_SUCCESS", status="SUCCESS", details={"verified_email": company_email}, company_id_override=pending_id)

            session.pop("pending_company_id", None)
            session.pop("debug_last_otp", None)
            session.pop("otp_delivery", None)

            flash("✅ Company verified successfully! Please login.", "success")
            return redirect(url_for("company_login"))
        else:
            cursor.execute("""
                UPDATE companies
                SET otp_attempts = COALESCE(otp_attempts, 0) + 1
                WHERE id = ?
            """, (pending_id,))
            conn.commit()
            conn.close()

            log_action("OTP_VERIFY_FAIL", status="FAIL", details={"reason": "incorrect_otp"}, company_id_override=pending_id)
            flash("Incorrect OTP. Try again.", "danger")
            return redirect(url_for("verify_company_otp"))

    conn.close()
    company_email = session.get("pending_company_email") or company_email
    otp_delivery = session.get("otp_delivery", "NULL")
    debug_last_otp = session.get("debug_last_otp")

    return render_template(
        "verify_company_otp.html",
        company_email=company_email,
        otp_delivery=otp_delivery,
        debug_last_otp=debug_last_otp
    )

# =====================================================
#                RESEND OTP (COOLDOWN)
# =====================================================
@app.route("/resend_company_otp")
def resend_company_otp():
    pending_id = session.get("pending_company_id")
    if not pending_id:
        flash("No pending verification found.", "warning")
        return redirect(url_for("company_login"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT company_email, COALESCE(is_verified,0), otp_last_sent_at
        FROM companies
        WHERE id = ?
    """, (pending_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        flash("Company not found.", "danger")
        return redirect(url_for("register_company"))

    company_email, is_verified, last_sent = row
    if int(is_verified or 0) == 1:
        conn.close()
        session.pop("pending_company_id", None)
        flash("Company already verified. Please login.", "success")
        return redirect(url_for("company_login"))

    last_dt = _safe_parse_dt(last_sent)
    if last_dt and (datetime.now() - last_dt).total_seconds() < 60:
        conn.close()
        flash("Please wait 60 seconds before requesting another OTP.", "info")
        return redirect(url_for("verify_company_otp"))

    otp = generate_otp(6)
    salt = secrets.token_hex(16)
    otp_h = hash_otp(otp, salt)
    expires = datetime.now() + timedelta(minutes=10)

    cursor.execute("""
        UPDATE companies
        SET otp_salt = ?, otp_hash = ?, otp_expires_at = ?, otp_attempts = 0, otp_last_sent_at = ?
        WHERE id = ?
    """, (salt, otp_h, expires, datetime.now(), pending_id))
    conn.commit()
    conn.close()

    sent = send_otp_email(company_email, otp)
    if sent:
        log_action("OTP_SENT", status="SUCCESS", details={"to": company_email, "type": "resend"}, company_id_override=pending_id)
        flash("New OTP sent to your email.", "success")
    else:
        log_action("OTP_SENT", status="FAIL", details={"to": company_email, "type": "resend", "note": "smtp_failed_demo_mode"}, company_id_override=pending_id)
        flash("Could not send OTP email (SMTP). OTP shown in server terminal for demo.", "warning")

    return redirect(url_for("verify_company_otp"))

# =====================================================
#         PUBLIC (NORMAL PEOPLE) SEND / RECEIVE
# =====================================================
def _public_code_exists(conn, code: str) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM public_transfers WHERE code=? LIMIT 1", (code,))
    return cur.fetchone() is not None

def _generate_unique_code(conn) -> str:
    for _ in range(20):
        code = generate_otp(6)
        if not _public_code_exists(conn, code):
            return code
    for _ in range(20):
        code = generate_otp(8)
        if not _public_code_exists(conn, code):
            return code
    raise RuntimeError("Could not generate unique code")

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

ALLOWED_PUBLIC_EXTS = {"pdf","png","jpg","jpeg","txt","doc","docx","ppt","pptx","xls","xlsx","zip"}

def _allowed_public_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_PUBLIC_EXTS

@app.route("/public", methods=["GET"])
def public_portal():
    return render_template("public_portal.html")

@app.route("/public/send", methods=["GET", "POST"])
def public_send():
    if request.method == "POST":
        files = request.files.getlist("files")

        if not files or all(f.filename == "" for f in files):
            flash("Please choose at least one file.", "danger")
            return redirect(url_for("public_send"))

        conn = get_db()
        cur = conn.cursor()

        code = _generate_unique_code(conn)
        expires = datetime.now() + timedelta(minutes=30)
        max_downloads = 1

        uploaded_files = []

        for file in files:
            original_name = secure_filename(file.filename)

            if not _allowed_public_file(original_name):
                flash(f"File type not allowed: {original_name}", "danger")
                continue

            stored_name = f"{secrets.token_hex(16)}_{original_name}"
            path = os.path.join(PUBLIC_UPLOAD_FOLDER, stored_name)
            file_data = file.read()

            temp_path = save_temp_file(file_data, original_name)
            vt_result = vt_lookup_or_submit(temp_path)

            if os.path.exists(temp_path):
                os.remove(temp_path)

            if not vt_result.get("ok"):
                conn.close()
                flash("Virus scan failed. Try again later.", "danger")
                return redirect(url_for("public_send"))

            if vt_result["status"] == "completed":
                malicious = vt_result["malicious"] or 0

                if malicious > 0:
                    conn.close()
                    flash(f"{malicious} antivirus engines detected malware in file: {original_name}", "danger")
                    return redirect(url_for("public_send"))

            elif vt_result["status"] == "queued":
                conn.close()
                flash(
                    f"Virus scan for '{original_name}' is taking longer than usual. Please try again in a few moments.",
                    "warning"
                )
                return redirect(url_for("public_send"))

            encrypted_data = encrypt_file_bytes(file_data)

            with open(path, "wb") as f:
                f.write(encrypted_data)

            sha = _sha256_file(path)

            cur.execute("""
                INSERT INTO public_transfers
                (code, filename, original_name, sha256, uploader_ip, expires_at, max_downloads)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                code,
                stored_name,
                original_name,
                sha,
                _get_client_ip(),
                expires,
                max_downloads
            ))

            uploaded_files.append(original_name)

        conn.commit()
        conn.close()

        if not uploaded_files:
            flash("No files uploaded.", "danger")
            return redirect(url_for("public_send"))

        log_public("PUBLIC_SEND", status="SUCCESS", details={
            "code": code,
            "files": uploaded_files
        })

        return render_template(
            "public_send_success.html",
            code=code,
            files=uploaded_files,
            expires_minutes=30
        )

    return render_template("public_send.html")

@app.route("/public/receive", methods=["GET", "POST"])
def public_receive():
    if request.method == "POST":
        code = (request.form.get("code") or "").strip()

        if not code.isdigit() or len(code) not in (6, 8):
            flash("Please enter a valid receive code.", "danger")
            return redirect(url_for("public_receive"))

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            SELECT id, filename, original_name, sha256, expires_at, download_count, max_downloads
            FROM public_transfers
            WHERE code = ?
        """, (code,))

        rows = cur.fetchall()
        conn.close()

        if not rows:
            log_public("PUBLIC_RECEIVE_LOOKUP", status="DENIED", details={"code": code, "reason": "not_found"})
            flash("Code not found or expired.", "danger")
            return redirect(url_for("public_receive"))

        # check expiration using first row
        exp_dt = _safe_parse_dt(rows[0][4])
        if exp_dt and datetime.now() > exp_dt:
            log_public("PUBLIC_RECEIVE_LOOKUP", status="DENIED", details={"code": code, "reason": "expired"})
            flash("This code has expired.", "danger")
            return redirect(url_for("public_receive"))

        # check downloads
        download_count = rows[0][5]
        max_downloads = rows[0][6]

        if int(download_count or 0) >= int(max_downloads or 1):
            log_public("PUBLIC_RECEIVE_LOOKUP", status="DENIED", details={"code": code, "reason": "already_downloaded"})
            flash("This code has already been used.", "danger")
            return redirect(url_for("public_receive"))

        files = []
        for r in rows:
            files.append({
                "id": r[0],
                "stored": r[1],
                "name": r[2]
            })

        return render_template(
            "public_receive_ready.html",
            code=code,
            files=files
        )

    return render_template("public_receive.html")

@app.route("/public/download/<int:file_id>", methods=["GET"])
def public_download(file_id):

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, code, filename, original_name, sha256, expires_at, download_count, max_downloads
        FROM public_transfers
        WHERE id = ?
    """, (file_id,))

    row = cur.fetchone()

    if not row:
        conn.close()
        abort(404)

    tid, code, stored_name, original_name, sha, expires_at, download_count, max_downloads = row

    exp_dt = _safe_parse_dt(expires_at)
    if exp_dt and datetime.now() > exp_dt:
        conn.close()
        abort(404)

    if int(download_count or 0) >= int(max_downloads or 1):
        conn.close()
        abort(404)

    cur.execute("""
        UPDATE public_transfers
        SET download_count = COALESCE(download_count,0) + 1,
            downloaded_at = ?
        WHERE id = ?
    """, (datetime.now(), tid))

    conn.commit()
    conn.close()

    path = os.path.join(PUBLIC_UPLOAD_FOLDER, stored_name)

    with open(path, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_file_bytes(encrypted_data)

    return send_file(
        BytesIO(decrypted_data),
        as_attachment=True,
        download_name=original_name
    )

# =====================================================
#               PORTAL SELECTION (enterprise)
# =====================================================
@app.route('/portal_select', methods=['GET','POST'])
def portal_select():
    if 'company_id' not in session:
        return redirect(url_for('company_login'))
    return render_template("portal_select.html", company=session.get('company_name'))

# =====================================================
#               EMPLOYEE LOGIN
# =====================================================
@app.route('/employee_login/<role>', methods=['GET', 'POST'])
def employee_login(role):
    if 'company_id' not in session:
        return redirect(url_for('company_login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, password FROM users
            WHERE username=? AND role=? AND company_id=?
        """, (username, role, session['company_id']))

        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = role
            session['tab_session_key'] = secrets.token_hex(16)
            session['tab_bootstrap_pending'] = True
            session.permanent = True

            log_action("USER_LOGIN", status="SUCCESS", details={"role": role})

            if role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif role == 'it':
                return redirect(url_for('it_dashboard'))
            else:
                return redirect(url_for('staff_dashboard'))
        else:
            log_action("USER_LOGIN", status="FAIL", details={"role": role, "username": username})
            flash("Invalid credentials", "danger")

    return render_template("employee_login.html", role=role)

# =====================================================
#               ADMIN DASHBOARD
# =====================================================
@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('company_login'))

    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password_raw = request.form.get('password') or ''
        role = (request.form.get('role') or '').strip()

        if not username or not password_raw or role not in ("staff", "it"):
            flash("Please fill all fields correctly.", "danger")
        else:
            password_hash = generate_password_hash(password_raw)

            try:
                cursor.execute("""
                    INSERT INTO users (username, password, role, company_id)
                    VALUES (?, ?, ?, ?)
                """, (username, password_hash, role, session['company_id']))
                conn.commit()
                flash(f"{role.capitalize()} user created: {username}", "success")

                try:
                    log_action("CREATED_USER", status="SUCCESS",
                               target_user=username,
                               details={"created_role": role, "created_username": username})
                except Exception:
                    pass

            except sqlite3.IntegrityError:
                conn.rollback()
                flash("Username already exists (try another).", "danger")

    cursor.execute("""
        SELECT id, username, role
        FROM users
        WHERE company_id=?
        ORDER BY role, username
    """, (session['company_id'],))
    users = cursor.fetchall()
    conn.close()

    return render_template('admin_dashboard.html',
                           users=users,
                           company=session.get('company_name') or session.get('company') or "NULL")

@app.route("/delete_user", methods=["POST"])
def delete_user():
    if session.get("role") != "admin":
        flash("Access denied.", "danger")
        return redirect(url_for("company_login"))

    user_id_raw = request.form.get("user_id")
    try:
        user_id = int(user_id_raw)
    except Exception:
        flash("Invalid user id.", "danger")
        return redirect(url_for("admin_dashboard"))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, username, role
        FROM users
        WHERE id = ? AND company_id = ?
    """, (user_id, session.get("company_id")))
    row = cursor.fetchone()

    if not row:
        conn.close()
        flash("User not found for this company.", "warning")
        return redirect(url_for("admin_dashboard"))

    _, username, role = row

    if role == "admin":
        conn.close()
        flash("You cannot delete an admin user.", "danger")
        return redirect(url_for("admin_dashboard"))

    cursor.execute("DELETE FROM users WHERE id = ? AND company_id = ?", (user_id, session.get("company_id")))
    conn.commit()
    conn.close()

    try:
        log_action("DELETE_USER", status="SUCCESS", target_user=username, details={"deleted_role": role, "user_id": user_id})
    except Exception:
        pass

    flash(f"User deleted: {username}", "success")
    return redirect(url_for("admin_dashboard"))

# =====================================================
#               IT DASHBOARD
# =====================================================
@app.route('/it', methods=['GET', 'POST'])
def it_dashboard():
    if 'role' not in session or session['role'] != 'it':
        return redirect(url_for('company_login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE role='staff' AND company_id=?", (session['company_id'],))
    staff = cursor.fetchall()

    username_to_id = {u: i for (i, u) in staff}
    id_to_username = {str(i): u for (i, u) in staff}

    if request.method == 'POST':
        files = request.files.getlist('files')
        selected_ids = request.form.getlist('staff_ids')
        selected_users = request.form.getlist('users')

        valid_files = [f for f in files if f and f.filename.strip()]

        if not valid_files:
            flash("Please choose at least one file.", "danger")
            conn.close()
            return redirect(url_for('it_dashboard'))

        if not selected_ids and not selected_users:
            flash("Please select at least one staff member.", "danger")
            conn.close()
            return redirect(url_for('it_dashboard'))

        targets = []
        for sid in selected_ids:
            sid_str = str(sid).strip()
            if sid_str in id_to_username:
                targets.append((int(sid_str), id_to_username[sid_str]))

        for uname in selected_users:
            uname = (uname or "").strip()
            if uname in username_to_id:
                targets.append((int(username_to_id[uname]), uname))

        targets = list({(sid, uname) for (sid, uname) in targets})

        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        saved_names = []

        for file in valid_files:
            original_name = secure_filename(file.filename)
            stored_name = f"{secrets.token_hex(8)}_{original_name}"
            filepath = os.path.join(UPLOAD_FOLDER, stored_name)

            file_data = file.read()

            temp_path = save_temp_file(file_data, original_name)
            vt_result = vt_lookup_or_submit(temp_path)

            if os.path.exists(temp_path):
                os.remove(temp_path)

            if not vt_result.get("ok"):
                conn.close()
                flash("Virus scan failed. Try again later.", "danger")
                return redirect(url_for('it_dashboard'))

            if vt_result["status"] == "completed":
                malicious = vt_result["malicious"] or 0

                if malicious > 0:
                    conn.close()
                    flash(f"{malicious} antivirus engines detected malware in file: {original_name}", "danger")
                    return redirect(url_for('it_dashboard'))

            elif vt_result["status"] == "queued":
                conn.close()
                flash(f"File '{original_name}' is still being scanned. Please try again in a short while.", "warning")
                return redirect(url_for('it_dashboard'))

            encrypted_data = encrypt_file_bytes(file_data)

            with open(filepath, "wb") as f:
                f.write(encrypted_data)

            saved_names.append(original_name)

            for staff_id, assigned_to in targets:
                cursor.execute("""
                    INSERT INTO files (filename, original_name, uploaded_by, assigned_to, staff_id, company_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    stored_name,
                    original_name,
                    session.get('username'),
                    assigned_to,
                    staff_id,
                    session.get('company_id')
                ))

        conn.commit()

        log_action(
            "FILE_UPLOAD",
            status="SUCCESS",
            details={
                "file_count": len(saved_names),
                "files": saved_names,
                "staff_ids": [t[0] for t in targets]
            }
        )

        flash(f"{len(saved_names)} file(s) sent successfully.", "success")
        conn.close()
        return redirect(url_for('it_dashboard'))

    conn.close()
    return render_template("it_dashboard.html", staff=staff, company=session.get('company_name'))
# =====================================================
#               STAFF DASHBOARD
# =====================================================
@app.route('/staff')
def staff_dashboard():
    if 'role' not in session or session['role'] != 'staff':
        return redirect(url_for('company_login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, filename, uploaded_by, timestamp AS upload_time
        FROM files
        WHERE staff_id = ? AND company_id = ?
        ORDER BY timestamp DESC
    """, (session['user_id'], session['company_id']))
    files = cursor.fetchall()
    conn.close()

    return render_template("staff_dashboard.html", files=files, company=session.get('company_name'))

@app.route('/download/<filename>')
def download(filename):
    if 'role' not in session or session.get('role') != 'staff':
        log_action("FILE_DOWNLOAD", status="DENIED", file_name=filename, details={"reason": "not_logged_in_or_not_staff"})
        return redirect(url_for('company_login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, original_name
        FROM files
        WHERE filename = ? AND staff_id = ? AND company_id = ?
        ORDER BY timestamp DESC
        LIMIT 1
    """, (filename, session.get('user_id'), session.get('company_id')))
    row = cursor.fetchone()
    conn.close()

    if not row:
        log_action("FILE_DOWNLOAD", status="DENIED", file_name=filename, details={"reason": "not_assigned_or_not_found"})
        flash("Access denied or file not found.", "danger")
        return redirect(url_for('staff_dashboard'))

    file_id, original_name = row
    log_action("FILE_DOWNLOAD", status="SUCCESS", file_id=file_id, file_name=original_name)
    with open(os.path.join(UPLOAD_FOLDER, filename), "rb") as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_file_bytes(encrypted_data)

    return send_file(
        BytesIO(decrypted_data),
        as_attachment=True,
        download_name=original_name
    )

# =====================================================
#               AUDIT LOG VIEW (admin)
# =====================================================

@app.route('/audit')
def audit_logs():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('company_login'))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            status,
            username,
            role,
            ip_address,
            method,
            endpoint,
            action,
            file_name,
            target_user,
            details
        FROM audit_logs
        WHERE company_id = ?
        ORDER BY id DESC
        LIMIT 500
    """, (session.get("company_id"),))

    rows = cursor.fetchall()
    conn.close()

    logs = []
    for row in rows:
        row = list(row)

        # 🔥 convert timestamp (index 1)
        row[1] = to_dubai_time(row[1])

        logs.append(row)

    return render_template("audit_logs.html", logs=logs)

@app.route("/chat/unread_count")
def chat_unread_count():
    if not session.get("user_id") and not root_required():
        return {"ok": False, "count": 0}, 200

    my_id = session.get("user_id")
    is_root = root_required()

    conn = get_db()
    cur = conn.cursor()

    if is_root:
        cur.execute("""
            SELECT COUNT(*)
            FROM chats c
            JOIN chat_messages m ON m.chat_id = c.id
            LEFT JOIN chat_reads r
              ON r.chat_id = c.id AND r.is_root = 1 AND r.user_id IS NULL
            WHERE m.sender_type != 'root'
              AND m.id > COALESCE(r.last_read_message_id, 0)
        """)
    else:
        cur.execute("""
            SELECT COUNT(*)
            FROM chats c
            JOIN chat_messages m ON m.chat_id = c.id
            LEFT JOIN chat_reads r
              ON r.chat_id = c.id AND r.user_id = ? AND r.is_root = 0
            WHERE ? IN (COALESCE(c.user1_id,0), COALESCE(c.user2_id,0))
              AND COALESCE(m.sender_user_id, -1) != ?
              AND m.sender_type != 'visitor'
              AND m.id > COALESCE(r.last_read_message_id, 0)
        """, (my_id, my_id, my_id))

    count = cur.fetchone()[0] or 0
    conn.close()

    return {"ok": True, "count": count}

@app.route("/chat/thread/<int:chat_id>/mark_read", methods=["POST"])
def chat_mark_read(chat_id):
    if not session.get("user_id") and not root_required():
        return {"ok": False, "error": "login required"}, 401

    my_id = session.get("user_id")
    is_root = root_required()

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT chat_type, company_id, COALESCE(user1_id,0), COALESCE(user2_id,0), COALESCE(visitor_token,'')
        FROM chats
        WHERE id=?
    """, (chat_id,))
    chat_row = cur.fetchone()
    conn.close()

    if not chat_row:
        return {"ok": False, "error": "chat not found"}, 404

    if not _can_access_chat(chat_row, int(my_id or 0), is_root):
        return {"ok": False, "error": "denied"}, 403

    _mark_chat_as_read(chat_id, my_id, is_root)
    return {"ok": True}
# =====================================================
#               LOGOUT
# =====================================================
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()
cursor.execute("PRAGMA table_info(chat_messages)")
print(cursor.fetchall())
conn.close()

if __name__ == "__main__":
    init_db()
    print("ROOT_USER =", os.getenv("ROOT_USER"))
    print("ROOT_PASS exists =", bool(os.getenv("ROOT_PASS")))
    print("DATABASE =", DATABASE)
    app.run(debug=True)
