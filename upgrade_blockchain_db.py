import sqlite3
import hashlib
import datetime

def upgrade_audit_table():
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    
    # Check if audit_logs already has the blockchain columns
    cursor.execute("PRAGMA table_info(audit_logs)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if 'block_hash' not in columns:
        print("Upgrading audit_logs table to support Blockchain architecture...")
        # Drop old plain-text log table to cleanly initialize the genesis blockchain
        cursor.execute("DROP TABLE IF EXISTS audit_logs")
        
        cursor.execute('''
            CREATE TABLE audit_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                block_hash TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # Insert a Genesis Block to bootstrap the chain
        genesis_prev = "0" * 64
        genesis_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        genesis_payload = f"0|SYSTEM_INIT|{genesis_time}|SUCCESS|{genesis_prev}"
        genesis_hash = hashlib.sha256(genesis_payload.encode()).hexdigest()
        
        cursor.execute('''
            INSERT INTO audit_logs (user_id, action, timestamp, status, previous_hash, block_hash)
            VALUES (NULL, 'SYSTEM_INIT: Genesis Block Created', ?, 'SUCCESS', ?, ?)
        ''', (genesis_time, genesis_prev, genesis_hash))
        
        conn.commit()
        print("✅ Blockchain Audit Ledger successfully initialized with Genesis Block!")
    else:
        print("⚠️ Blockchain columns already exist in audit_logs!")
        
    conn.close()

if __name__ == '__main__':
    upgrade_audit_table()