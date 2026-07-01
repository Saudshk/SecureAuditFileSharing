import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")

def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Check existing columns
    cur.execute("PRAGMA table_info(chat_messages)")
    cols = [r[1] for r in cur.fetchall()]
    if not cols:
        print("❌ chat_messages table not found. Run your app once to create tables.")
        conn.close()
        return

    has_thread_id = "thread_id" in cols
    has_chat_id = "chat_id" in cols

    if not has_thread_id:
        print("✅ No thread_id column exists. Nothing to fix.")
        conn.close()
        return

    print("ℹ️ Found thread_id in chat_messages. Migrating to chat_id...")

    # Create new table with the correct schema (chat_id)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS chat_messages_new (
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

    # Copy data:
    # If chat_id exists already, use it; otherwise map thread_id -> chat_id.
    if has_chat_id:
        cur.execute("""
            INSERT INTO chat_messages_new (id, chat_id, sender_type, sender_user_id, sender_name, message, file_id, created_at)
            SELECT id, COALESCE(chat_id, thread_id), sender_type, sender_user_id, sender_name, message, file_id, created_at
            FROM chat_messages
        """)
    else:
        cur.execute("""
            INSERT INTO chat_messages_new (id, chat_id, sender_type, sender_user_id, sender_name, message, file_id, created_at)
            SELECT id, thread_id, sender_type, sender_user_id, sender_name, message, file_id, created_at
            FROM chat_messages
        """)

    # Replace old table
    cur.execute("DROP TABLE chat_messages")
    cur.execute("ALTER TABLE chat_messages_new RENAME TO chat_messages")

    conn.commit()
    conn.close()
    print("✅ Migration complete. chat_messages now uses chat_id (thread_id removed).")

if __name__ == "__main__":
    main()