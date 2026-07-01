import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")

def col_exists(cur, table: str, col: str) -> bool:
    cur.execute(f"PRAGMA table_info({table})")
    return any(r[1] == col for r in cur.fetchall())

def ensure_table(cur, ddl: str):
    cur.execute(ddl)

def add_col_if_missing(cur, table: str, col: str, col_type: str):
    if not col_exists(cur, table, col):
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
        print(f"Added {table}.{col}")
    else:
        print(f"Exists {table}.{col}")

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # ---- chats (supports company + admin_to_root + root_public)
    ensure_table(cur, """
    CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_type TEXT NOT NULL,
        company_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_by_user_id INTEGER,
        visitor_token TEXT,
        user1_id INTEGER,
        user2_id INTEGER
    )
    """)

    # In case chats existed earlier with fewer columns:
    add_col_if_missing(cur, "chats", "chat_type", "TEXT")
    add_col_if_missing(cur, "chats", "company_id", "INTEGER")
    add_col_if_missing(cur, "chats", "created_at", "DATETIME")
    add_col_if_missing(cur, "chats", "created_by_user_id", "INTEGER")
    add_col_if_missing(cur, "chats", "visitor_token", "TEXT")
    add_col_if_missing(cur, "chats", "user1_id", "INTEGER")
    add_col_if_missing(cur, "chats", "user2_id", "INTEGER")

    # ---- chat_messages
    ensure_table(cur, """
    CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        sender_type TEXT NOT NULL,
        sender_user_id INTEGER,
        sender_name TEXT,
        message TEXT,
        file_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(chat_id) REFERENCES chats(id)
    )
    """)

    add_col_if_missing(cur, "chat_messages", "chat_id", "INTEGER")
    add_col_if_missing(cur, "chat_messages", "sender_type", "TEXT")
    add_col_if_missing(cur, "chat_messages", "sender_user_id", "INTEGER")
    add_col_if_missing(cur, "chat_messages", "sender_name", "TEXT")
    add_col_if_missing(cur, "chat_messages", "message", "TEXT")
    add_col_if_missing(cur, "chat_messages", "file_id", "INTEGER")
    add_col_if_missing(cur, "chat_messages", "created_at", "DATETIME")

    # ---- announcements
    ensure_table(cur, """
    CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    add_col_if_missing(cur, "announcements", "title", "TEXT")
    add_col_if_missing(cur, "announcements", "body", "TEXT")
    add_col_if_missing(cur, "announcements", "created_at", "DATETIME")

    conn.commit()
    conn.close()
    print("Migration complete.")

if __name__ == "__main__":
    main()
