import sqlite3
import os

db_path = "instance/users.db"

if not os.path.exists(db_path):
    print(f"{db_path}: File does not exist")
else:
    print(f"\n{'='*50}")
    print(f"Database: {db_path}")
    print(f"File size: {os.path.getsize(db_path)} bytes")
    print(f"{'='*50}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    print(f"Tables: {[t[0] for t in tables]}")
    
    # Check user count
    try:
        cursor.execute("SELECT COUNT(*) FROM user")
        count = cursor.fetchone()[0]
        print(f"User count: {count}")
        
        # Show all users
        if count > 0:
            cursor.execute("SELECT id, first_name, last_name, email, phone FROM user")
            users = cursor.fetchall()
            print(f"\nUsers:")
            for user in users:
                print(f"  ID: {user[0]}, Name: {user[1]} {user[2]}, Email: {user[3]}, Phone: {user[4]}")
        else:
            print("\nNo users found. Database is empty but schema exists.")
    except Exception as e:
        print(f"Error reading users: {e}")
    
    conn.close()
