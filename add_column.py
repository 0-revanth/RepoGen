import sqlite3
import os

db_path = 'users.db'

if not os.path.exists(db_path):
    print(f"Error: {db_path} not found!")
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    # Check current schema
    cursor.execute("PRAGMA table_info(user)")
    columns = cursor.fetchall()
    column_names = [col[1] for col in columns]
    
    print("Current columns:", column_names)
    
    if 'profile_picture' not in column_names:
        print("\nAdding profile_picture column...")
        cursor.execute("ALTER TABLE user ADD COLUMN profile_picture VARCHAR(200) DEFAULT NULL")
        conn.commit()
        print("✓ Column added successfully!")
    else:
        print("\n✓ Column already exists!")
    
    # Verify
    cursor.execute("PRAGMA table_info(user)")
    columns = cursor.fetchall()
    print("\nFinal schema:")
    for col in columns:
        print(f"  - {col[1]} ({col[2]})")
    
    # Check if there are users
    cursor.execute("SELECT COUNT(*) FROM user")
    user_count = cursor.fetchone()[0]
    print(f"\nTotal users in database: {user_count}")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    conn.rollback()
finally:
    conn.close()

print("\nDone! Please restart your Flask server.")
