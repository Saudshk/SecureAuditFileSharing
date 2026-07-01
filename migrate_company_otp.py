import sqlite3

DB = "database.db"

conn = sqlite3.connect(DB)
cur = conn.cursor()

cur.execute("PRAGMA table_info(companies)")
cols = {row[1] for row in cur.fetchall()}

to_add = {
    "is_verified": "INTEGER DEFAULT 0",
    "otp_salt": "TEXT",
    "otp_hash": "TEXT",
    "otp_expires_at": "DATETIME",
    "otp_attempts": "INTEGER DEFAULT 0",
    "otp_last_sent_at": "DATETIME"
}

for c, t in to_add.items():
    if c not in cols:
        cur.execute(f"ALTER TABLE companies ADD COLUMN {c} {t}")
        print("Added:", c)
    else:
        print("Exists:", c)

conn.commit()
conn.close()
print("✅ Company OTP migration complete")