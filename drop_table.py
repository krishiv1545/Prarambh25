import sqlite3

conn = sqlite3.connect('instance/project_db.sqlite3')
cursor = conn.cursor()

cursor.execute("DROP TABLE IF EXISTS killswitch")  # change name

conn.commit()
conn.close()
