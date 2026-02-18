import sqlite3

db_path = 'instance/users.db'

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    # Check current columns
    cursor.execute("PRAGMA table_info(user)")
    columns = cursor.fetchall()
    column_names = [col[1] for col in columns]
    
    print("Current columns:", column_names)
    
    if 'profile_picture' not in column_names:
        print("\nAdding profile_picture column...")
        cursor.execute("ALTER TABLE user ADD COLUMN profile_picture VARCHAR(200)")
        conn.commit()
        print("✓ Column added successfully!")
    else:
        print("\n✓ Column profile_picture already exists!")
    
    # Verify the change
    cursor.execute("PRAGMA table_info(user)")
    columns = cursor.fetchall()
    print("\nUpdated schema:")
    for col in columns:
        print(f"  - {col[1]} ({col[2]})")
    
    # Check users
    cursor.execute("SELECT COUNT(*) FROM user")
    print(f"\nTotal users: {cursor.fetchone()[0]}")
    
except Exception as e:
    print(f"Error: {e}")
    conn.rollback()
finally:
    conn.close()

print("\n✓ Database updated! Please restart your server.")
