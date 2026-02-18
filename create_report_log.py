import sqlite3
import os

db_path = 'instance/users.db'

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    print("Creating report_log table...")
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS report_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        organization_code VARCHAR(50) NOT NULL,
        report_code VARCHAR(50) UNIQUE NOT NULL,
        project_name VARCHAR(100) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES user (id)
    )
    ''')
    conn.commit()
    print("report_log table created successfully!")
    
    # Verify
    cursor.execute("PRAGMA table_info(report_log)")
    columns = cursor.fetchall()
    print("\nTable schema:")
    for col in columns:
        print(col)

except Exception as e:
    print(f"Error: {e}")
    conn.rollback()
finally:
    conn.close()
