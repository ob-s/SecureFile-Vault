import sqlite3
import pyotp

def upgrade_database():
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    
    try:
        # Add the new column for the Google Authenticator secret
        cursor.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
        
        # Retroactively generate secrets for your existing test accounts (admin, berry, etc.)
        cursor.execute("SELECT user_id FROM users")
        for row in cursor.fetchall():
            secret = pyotp.random_base32()
            cursor.execute("UPDATE users SET totp_secret = ? WHERE user_id = ?", (secret, row[0]))
            
        conn.commit()
        print("✅ Database successfully upgraded for MFA/2FA support.")
    except sqlite3.OperationalError:
        print("⚠️ The totp_secret column already exists. You are good to go!")
        
    conn.close()

if __name__ == '__main__':
    upgrade_database()