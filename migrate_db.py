"""
Database migration script to add profile_picture column to existing users.db
This preserves all existing user data.
"""

import sqlite3
import shutil
import os
from datetime import datetime

# Backup the database first
db_path = 'instance/users.db'
backup_path = f'instance/users_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'

if os.path.exists(db_path):
    print(f"Creating backup: {backup_path}")
    shutil.copy2(db_path, backup_path)
    print("Backup created successfully!")

# Connect to the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    # Define columns to add
    new_columns = {
        'organization_code': 'VARCHAR(50)',
        'is_admin': 'BOOLEAN DEFAULT 0',
        'organization_name': 'VARCHAR(200)'
    }

    # Check existing columns
    cursor.execute("PRAGMA table_info(user)")
    existing_columns = [column[1] for column in cursor.fetchall()]
    
    for col_name, col_type in new_columns.items():
        if col_name in existing_columns:
            print(f"Column '{col_name}' already exists!")
        else:
            # Add the new column
            print(f"Adding '{col_name}' column...")
            cursor.execute(f"ALTER TABLE user ADD COLUMN {col_name} {col_type}")
            conn.commit()
            print(f"Column '{col_name}' added successfully!")
        
    # Verify the columns were added
    cursor.execute("PRAGMA table_info(user)")
    columns = cursor.fetchall()
    print("\nCurrent table schema:")
    for col in columns:
        print(f"  - {col[1]} ({col[2]})")
        
except Exception as e:
    print(f"Error: {e}")
    conn.rollback()
finally:
    conn.close()

print("\nMigration complete!")
