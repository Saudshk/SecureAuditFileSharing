import sqlite3

def create_files_table():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        uploader TEXT NOT NULL,
        assigned_to TEXT NOT NULL,  -- comma-separated usernames
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    conn.commit()
    conn.close()
    print("Files table created successfully.")

if __name__ == "__main__":
    create_files_table()
