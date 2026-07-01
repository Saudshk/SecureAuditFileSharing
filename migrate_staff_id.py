import sqlite3

DB = "database.db"  # make sure this is the same DB your app uses

conn = sqlite3.connect(DB)
cur = conn.cursor()

cur.execute("PRAGMA table_info(audit_logs)")
cols = {row[1] for row in cur.fetchall()}

if "staff_id" not in cols:
    cur.execute("ALTER TABLE audit_logs ADD COLUMN staff_id INTEGER")
    conn.commit()
    print("✅ Added staff_id column to audit_logs")
else:
    print("ℹ️ staff_id already exists")

conn.close()