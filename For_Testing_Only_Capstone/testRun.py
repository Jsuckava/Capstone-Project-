import psycopg2
import hashlib

DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'postgres',
    'user': 'apple',
    'password': ''
}

def hash_sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def fresh_setup():
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = True
    cur = conn.cursor()
    
    cur.execute("DROP TABLE IF EXISTS users;")
    
    cur.execute("""
    CREATE TABLE users (
        userid SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(64) NOT NULL,
        role VARCHAR(10) NOT NULL
    );
    """)
    
    admin_username = 'admin'
    admin_password = 'admin123'  
    hashed_password = hash_sha256(admin_password)
    
    cur.execute("INSERT INTO users(username, password, role) VALUES(%s, %s, 'admin')",
                (admin_username, hashed_password))
    
    print(f"[Setup Complete] Default admin created: {admin_username} / {admin_password}")
    cur.close()
    conn.close()

if __name__ == "__main__":
    fresh_setup()
