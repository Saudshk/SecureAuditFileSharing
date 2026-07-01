# migrate_chat_notifications.py
import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")

def table_exists(cur, table_name: str) -> bool:
    cur.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type='table' AND name=?
    """, (table_name,))
    return cur.fetchone() is not None

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS chat_reads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER,
        is_root INTEGER DEFAULT 0,
        last_read_message_id INTEGER DEFAULT 0,
        UNIQUE(chat_id, user_id, is_root)
    )
    """)

    conn.commit()
    conn.close()
    print("chat_reads migration complete.")

if __name__ == "__main__":
    main()