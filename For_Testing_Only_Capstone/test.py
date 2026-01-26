import psycopg2

conn = psycopg2.connect(
    host='localhost',
    port=5432,
    database='postgres',
    user='apple',
    password=''  
)
cur = conn.cursor()

cur.execute("DELETE FROM users;")
conn.commit()

cur.execute("ALTER SEQUENCE users_id_seq RESTART WITH 1;")
conn.commit()

cur.execute("SELECT * FROM users;")
print(cur.fetchall())  
cur.close()
conn.close()

print("All users including admins have been deleted!")
