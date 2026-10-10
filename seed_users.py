import sqlite3
from werkzeug.security import generate_password_hash

DATABASE = 'vault.db'

def seed_test_accounts():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Check if the table is already populated to avoid duplicates
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] > 0:
        print("Database already contains users. Skipping seed.")
        conn.close()
        return

    # Generate secure hashes for the test passwords
    admin_password = generate_password_hash("AdminPass2026!")
    accountant_password = generate_password_hash("AccPass2026!")

    # 1. Insert the Administrator
    cursor.execute('''
        INSERT INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
    ''', ('administrator', admin_password, 'Admin'))

    # 2. Insert Accountant: Mike
    cursor.execute('''
        INSERT INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
    ''', ('mike', accountant_password, 'Accountant'))

    # 3. Insert Accountant: Berry
    cursor.execute('''
        INSERT INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
    ''', ('berry', accountant_password, 'Accountant'))

    # 4. Insert Accountant: Moka
    cursor.execute('''
        INSERT INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
    ''', ('moka', accountant_password, 'Accountant'))

    conn.commit()
    conn.close()
    print("Successfully created test accounts: administrator, mike, berry, and moka.")

if __name__ == '__main__':
    seed_test_accounts()