import sqlite3

# Create or connect to DB
conn = sqlite3.connect('webshell.db')
cur = conn.cursor()

# === USERS TABLE ===
cur.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT,
    last_name TEXT,
    email TEXT,
    username TEXT UNIQUE,
    password TEXT
)
''')

# === SCAN RESULTS TABLE ===
cur.execute('''
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    result TEXT,
    status TEXT,  -- clean / malicious / unknown
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')

conn.commit()
conn.close()
print("✅ Database and tables created successfully.")
