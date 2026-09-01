import sqlite3
import os

# Check if database exists
db_files = ['aml.db', 'app.db', 'bank.db']
for db_file in db_files:
    if os.path.exists(db_file):
        print(f"Found: {db_file}")
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print(f"  Tables: {[t[0] for t in tables]}")
        conn.close()
        print()

# Also check the current directory
print("Current directory:", os.getcwd())
print("Files in directory:")
for f in os.listdir('.'):
    if f.endswith('.db'):
        print(f"  {f}")
