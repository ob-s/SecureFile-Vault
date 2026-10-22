import sqlite3
import os
import hashlib
import crypto_utils

DATABASE = 'vault.db'
VAULT_DIR = 'vault'

def get_aes_key(password):
    """Directly derives the 32-byte (256-bit) AES key from the password using SHA-256."""
    if isinstance(password, str):
        password = password.encode('utf-8')
    return hashlib.sha256(password).digest()

def run_smart_encrypt(data_bytes, password, filepath):
    """Encrypts the forged payload using crypto_utils.encrypt_file_data."""
    key = get_aes_key(password)
    ciphertext = crypto_utils.encrypt_file_data(data_bytes, key)
    
    with open(filepath, 'wb') as f:
        f.write(ciphertext)

def simulate_file_replacement():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # 1. Dynamically discover the exact column names in the 'files' table
    cursor.execute("PRAGMA table_info(files)")
    columns_info = cursor.fetchall()
    col_names = [col[1] for col in columns_info]
    
    if not col_names:
        print("❌ The 'files' table does not exist in vault.db!")
        conn.close()
        return

    id_col = next((c for c in col_names if 'id' in c.lower()), col_names[0])
    name_col = next((c for c in col_names if 'name' in c.lower()), col_names[1])
    hash_col = next((c for c in col_names if 'hash' in c.lower() or 'sha' in c.lower()), None)
    lock_col = next((c for c in col_names if 'admin' in c.lower() or 'lock' in c.lower()), None)
    path_col = next((c for c in col_names if 'path' in c.lower()), None)

    # 2. Fetch all files currently in the vault
    query_cols = [id_col, name_col]
    if hash_col: query_cols.append(hash_col)
    if lock_col: query_cols.append(lock_col)
    if path_col: query_cols.append(path_col)

    cursor.execute(f"SELECT {', '.join(query_cols)} FROM files")
    files = cursor.fetchall()
    
    if not files:
        print("❌ No files found in the vault! Log in as an Accountant and encrypt a file first.")
        conn.close()
        return

    print("\n================ CURRENT VAULT FILES ================")
    for f in files:
        f_id = f[0]
        f_name = f[1]
        f_status = "LOCKED" if (lock_col and f[query_cols.index(lock_col)]) else "ACTIVE"
        print(f"ID: [{f_id}] | File: {f_name:<20} | Status: {f_status}")
    print("=====================================================\n")

    target_id = input("Enter the ID number of the file you want to tamper with: ").strip()
    
    cursor.execute(f"SELECT {', '.join(query_cols)} FROM files WHERE {id_col} = ?", (target_id,))
    record = cursor.fetchone()
    conn.close()

    if not record:
        print("❌ Invalid File ID.")
        return

    target_filename = record[1]
    db_original_hash = record[query_cols.index(hash_col)] if hash_col else "Hash column not found"
    
    # 3. Locate the encrypted file on disk
    possible_paths = []
    if path_col and record[query_cols.index(path_col)]:
        possible_paths.append(record[query_cols.index(path_col)])
    possible_paths.extend([
        os.path.join(VAULT_DIR, target_filename + ".enc"),
        os.path.join(VAULT_DIR, target_filename),
        os.path.join("uploads", target_filename + ".enc"),
        os.path.join("uploads", target_filename)
    ])

    encrypted_filepath = next((p for p in possible_paths if os.path.exists(p)), None)

    if not encrypted_filepath:
        print(f"❌ Could not find the encrypted file on disk. Checked: {possible_paths}")
        return

    print(f"\n🎯 Target Selected : {target_filename} (Stored at: {encrypted_filepath})")
    print(f"🔒 Original SHA-256: {db_original_hash}")

    password = input(f"\nEnter the encryption password for '{target_filename}' to inject forged data: ")

    # 4. Create the fraudulent financial payload & re-encrypt with the 32-byte AES key
    forged_data = b"FRAUDULENT LEDGER MODIFICATION: Transfer $950,000 to Offshore Account #883920."
    forged_hash = hashlib.sha256(forged_data).hexdigest()

    run_smart_encrypt(forged_data, password, encrypted_filepath)

    print("\n INSIDER ATTACK EXECUTED SUCCESSFULLY!")
    print("-------------------------------------------------------------------------")
    print(f"Original SHA-256 (Expected) : {db_original_hash}")
    print(f"Tampered SHA-256 (Injected) : {forged_hash}")
    print("-------------------------------------------------------------------------")
    print("Now go to your browser and try to decrypt this file in the Accountant Dashboard!")

if __name__ == '__main__':
    simulate_file_replacement()