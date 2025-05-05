import sqlite3

def create_database():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        profile_pic TEXT DEFAULT 'default.png',
        facebook TEXT DEFAULT '',
        twitter TEXT DEFAULT '',
        linkedin TEXT DEFAULT '',
        description TEXT DEFAULT ''
    )
    """)

    # Create rsa_keys table for multi-user key support
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS rsa_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        public_key TEXT NOT NULL,
        private_key TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()

def get_db_connection():
    """Returns a connection to the SQLite database."""
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name
    return conn

if __name__ == "__main__":
    create_database()
    print("Database initialized successfully!")
