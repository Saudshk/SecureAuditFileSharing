import sqlite3
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

username = "admin"
password = "admin123"
role = "admin"

hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
               (username, hashed_password, role))

conn.commit()
conn.close()

print("Admin account created.")
