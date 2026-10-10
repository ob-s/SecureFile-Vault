import os
import sqlite3
import hashlib
from crypto_utils import encrypt_file_data

DATABASE = 'vault.db'

def simulate_file_replacement():
    """Simulates an attacker replacing the physical vault file with altered financial data."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Find the most recently uploaded file
    cursor.execute("SELECT file_id, filename, storage_path FROM files ORDER BY file_id DESC LIMIT 1")
    file_record = cursor.fetchone()
    conn.close()

    if not file_record:
        print("No files found in the vault. Please upload a file first.")
        return

    file_id, filename, storage_path = file_record
    
    print(f"Targeting file: {filename}")
    password = input("Enter the encryption password used for this file (simulating a stolen password): ")

    # 1. The attacker creates unauthorized, modified financial data
    malicious_data = b"FRAUDULENT INVOICE: Transfer $50,000 to offshore account #999-XYZ"
    
    # 2. Attacker derives the key from the stolen password
    encryption_key = hashlib.sha256(password.encode()).digest()
    
    # 3. Attacker encrypts the fraudulent data so it passes the AES-GCM check
    malicious_encrypted_data = encrypt_file_data(malicious_data, encryption_key)
    
    # 4. Attacker overwrites the original file in the vault
    with open(storage_path, 'wb') as f:
        f.write(malicious_encrypted_data)
        
    print(f"\n💀 BREACH SUCCESSFUL: The physical file '{storage_path}' has been replaced.")
    print("The AES encryption is valid, but the SHA-256 hash of the contents has changed.")

if __name__ == '__main__':
    simulate_file_replacement()