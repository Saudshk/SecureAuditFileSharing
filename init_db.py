import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# =======================
# Companies Table
# =======================
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
CREATE TABLE IF NOT EXISTS chat_reads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    user_id INTEGER,
    is_root INTEGER DEFAULT 0,
    last_read_message_id INTEGER DEFAULT 0,
    UNIQUE(chat_id, user_id, is_root)
)
""")
# =======================
# Users Table
# =======================
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    role TEXT,
    company_id INTEGER
)
""")

# =======================
# Files Table
# =======================
cursor.execute("""
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    original_name TEXT,
    uploaded_by TEXT,
    assigned_to TEXT,
    company_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# =======================
# Audit Logs Table (base)
# =======================
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
CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# Add OTP fields to companies if missing
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

def migrate_audit_logs(conn, cursor):
    # Get existing columns
    cursor.execute("PRAGMA table_info(audit_logs)")
    existing_columns = {row[1] for row in cursor.fetchall()}

    # Add extra informative columns (only if missing)
    new_columns = {
        "actor_user_id": "INTEGER",
        "ip_address": "TEXT",
        "user_agent": "TEXT",
        "endpoint": "TEXT",
        "method": "TEXT",
        "status": "TEXT",        # SUCCESS / FAIL / DENIED
        "file_id": "INTEGER",
        "file_name": "TEXT",
        "target_user": "TEXT",
        "details": "TEXT"
    }

    for col, col_type in new_columns.items():
        if col not in existing_columns:
            cursor.execute(f"ALTER TABLE audit_logs ADD COLUMN {col} {col_type}")
            print(f"Added column: {col}")
        else:
            print(f"Column already exists: {col}")

    conn.commit()
    print("Audit log migration complete.")

# Run migration safely
migrate_audit_logs(conn, cursor)

conn.close()