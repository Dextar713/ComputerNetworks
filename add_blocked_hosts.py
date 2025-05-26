import sqlite3

DB_NAME = "blacklist.db"
HOSTS_FILE = "spam_domains.txt"  # your hosts file path

# Connect to SQLite (it will create the DB if not exists)
if __name__ == '__main__':
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    # Create table if not exists
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL
        )
    """)

    # Open and parse hosts file
    with open(HOSTS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("0.0.0.0"):
                try:
                    _, domain = line.split(maxsplit=1)
                    cur.execute("INSERT OR IGNORE INTO blacklist (domain) VALUES (?)", (domain,))
                except ValueError:
                    continue  # skip malformed lines

    conn.commit()
    conn.close()
    print("Done: Imported blacklist into SQLite.")
