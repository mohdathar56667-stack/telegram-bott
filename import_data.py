
import json
import sqlite3
import hashlib
from datetime import datetime
import os

# Database setup
DB_DIR = "Database"
os.makedirs(DB_DIR, exist_ok=True)
DB_FILE = os.path.join(DB_DIR, "earner_community.db")

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def import_data():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Import users
    try:
        with open('attached_assets/users_1753317534821.json', 'r') as f:
            users_data = json.load(f)
            
        for user in users_data:
            # Hash password if it's not already hashed
            password = user['password'] if len(user['password']) == 64 else hash_password(user['password'])
            
            cursor.execute("""
                INSERT OR IGNORE INTO users (email, password, name, chat_id, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                user['email'].lower(),
                password,
                user['name'],
                user.get('chat_id'),
                user.get('created_at', datetime.now().isoformat())
            ))
        print(f"Imported {len(users_data)} users")
    except Exception as e:
        print(f"Error importing users: {e}")
    
    # Import activations
    try:
        with open('attached_assets/activations_1753317534943.json', 'r') as f:
            activations_data = json.load(f)
            
        for act in activations_data:
            cursor.execute("""
                INSERT OR IGNORE INTO activations 
                (email, mobile, app, status, reason, timestamp, submission_date, message_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                act['email'],
                act['mobile'].replace(" ", ""),
                act['app'],
                act.get('status', 'pending'),
                act.get('reason', '0'),
                act.get('timestamp', datetime.now().isoformat()),
                act.get('submission_date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                act.get('message_id')
            ))
        print(f"Imported {len(activations_data)} activations")
    except Exception as e:
        print(f"Error importing activations: {e}")
    
    # Import apps
    try:
        with open('attached_assets/ec_app_1753317534924.json', 'r') as f:
            apps_data = json.load(f)
            
        for app in apps_data:
            cursor.execute("""
                INSERT OR REPLACE INTO apps (name, report_time, report_updated, status)
                VALUES (?, ?, ?, ?)
            """, (
                app['name'],
                app['report_time'],
                app['report_updated'],
                app['status']
            ))
        print(f"Imported {len(apps_data)} apps")
    except Exception as e:
        print(f"Error importing apps: {e}")
    
    # Import guide
    try:
        with open('attached_assets/ec_guide_1753317534902.json', 'r') as f:
            guide_data = json.load(f)
            
        cursor.execute("""
            INSERT OR REPLACE INTO guides (id, title, content)
            VALUES (1, ?, ?)
        """, (guide_data['title'], guide_data['content']))
        print("Imported guide")
    except Exception as e:
        print(f"Error importing guide: {e}")
    
    # Import rules
    try:
        with open('attached_assets/ec_rules_1753317534879.json', 'r') as f:
            rules_data = json.load(f)
            
        cursor.execute("""
            INSERT OR REPLACE INTO rules (id, title, content)
            VALUES (1, ?, ?)
        """, (rules_data['title'], rules_data['content']))
        print("Imported rules")
    except Exception as e:
        print(f"Error importing rules: {e}")
    
    conn.commit()
    conn.close()
    print("Data import completed!")

if __name__ == '__main__':
    import_data()
