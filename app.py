import os
import sqlite3
import hashlib
import pyotp
import qrcode
import base64
import io
from flask import Flask, render_template, request, session, redirect, url_for, flash, send_file
from werkzeug.security import check_password_hash,generate_password_hash
from werkzeug.utils import secure_filename
from crypto_utils import encrypt_file_data, decrypt_file_data
import datetime

app = Flask(__name__)
# In a production app, use an environment variable for the secret key
app.config['SECRET_KEY'] = 'super-secret-key-for-development'
DATABASE = 'vault.db'

def init_db():
    """Initializes the SQLite database and creates the necessary tables."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # 1. User and Role Management Table (This was missing!)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            is_locked BOOLEAN DEFAULT 0
        )
    ''')

    # 2. Secure File Storage Table (With the new failed_decryption_attempts column)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            storage_path TEXT NOT NULL,
            integrity_hash TEXT NOT NULL,
            failed_decryption_attempts INTEGER DEFAULT 0,
            requires_admin BOOLEAN DEFAULT 0,
            FOREIGN KEY (owner_id) REFERENCES users (user_id)
        )
    ''')

    # 3. Operational Audit Logging Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')

    conn.commit()
    conn.close()

def log_audit_event(user_id, action, status):
    """Records security events into an immutable, cryptographically-linked blockchain ledger."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # 1. Fetch the block hash of the previous event to form the chain
    cursor.execute("SELECT block_hash FROM audit_logs ORDER BY log_id DESC LIMIT 1")
    last_block = cursor.fetchone()
    previous_hash = last_block[0] if last_block else "0" * 64
    
    # 2. Generate timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 3. Compute cryptographic block hash (Data + Previous Hash)
    payload = f"{user_id}|{action}|{timestamp}|{status}|{previous_hash}"
    block_hash = hashlib.sha256(payload.encode()).hexdigest()
    
    # 4. Commit block to the database
    cursor.execute('''
        INSERT INTO audit_logs (user_id, action, timestamp, status, previous_hash, block_hash)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, action, timestamp, status, previous_hash, block_hash))
    
    conn.commit()
    conn.close()

def verify_blockchain_ledger():
    """Mathematically verifies the immutability and integrity of the entire audit chain."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT log_id, user_id, action, timestamp, status, previous_hash, block_hash FROM audit_logs ORDER BY log_id ASC")
    logs = cursor.fetchall()
    conn.close()
    
    if not logs:
        return True, "Ledger is empty."
        
    expected_previous_hash = "0" * 64
    
    for log in logs:
        log_id, user_id, action, timestamp, status, previous_hash, block_hash = log
        
        # 1. Validate link to previous block
        if previous_hash != expected_previous_hash:
            return False, f"CHAIN INTEGRITY BREACH: Block #{log_id} has a broken previous hash pointer!"
            
        # 2. Recalculate block hash to check for unauthorized data modification
        payload = f"{user_id}|{action}|{timestamp}|{status}|{previous_hash}"
        recalculated_hash = hashlib.sha256(payload.encode()).hexdigest()
        
        if recalculated_hash != block_hash:
            return False, f"TAMPER DETECTED: Block #{log_id} payload has been altered in the database!"
            
        expected_previous_hash = block_hash
        
    return True, "Blockchain audit ledger is 100% cryptographically intact."

# --- ROUTES ---

@app.route('/')
def index():
    # If the user is already logged in, send them straight to the dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            flash("That username is already taken. Please choose another.", "danger")
            conn.close()
            return redirect(url_for('register'))
            
        hashed_pw = generate_password_hash(password)
        totp_secret = pyotp.random_base32() # Generate their unique MFA secret
        
        cursor.execute('''
            INSERT INTO users (username, password_hash, role, totp_secret) 
            VALUES (?, ?, 'Accountant', ?)
        ''', (username, hashed_pw, totp_secret))
        conn.commit()
        
        cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
        new_user_id = cursor.fetchone()[0]
        log_audit_event(new_user_id, "REGISTER_ACCOUNT", "SUCCESS")
        conn.close()
        
        # Route them straight to the MFA setup screen
        session['setup_2fa_user'] = username
        session['setup_2fa_secret'] = totp_secret
        return redirect(url_for('setup_2fa'))
        
    return render_template('register.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    # Enforce strict Role-Based Access Control (RBAC)
    if 'user_id' not in session or session.get('role') != 'Admin':
        flash("Unauthorized access. Admin privileges required.", "danger")
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Fetch all globally locked files needing Admin review
    cursor.execute('''
        SELECT f.file_id, f.filename, u.username, f.failed_decryption_attempts 
        FROM files f
        JOIN users u ON f.owner_id = u.user_id
        WHERE f.requires_admin = 1
    ''')
    locked_files = cursor.fetchall()
    conn.close()
    
    return render_template('admin_dashboard.html', files=locked_files)

@app.route('/admin/audit-logs')
def admin_audit_logs():
    if 'user_id' not in session or session.get('role') != 'Admin':
        return redirect(url_for('login'))
        
    # Verify chain integrity before displaying
    is_valid, message = verify_blockchain_ledger()
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT a.log_id, u.username, a.action, a.timestamp, a.status, a.block_hash 
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.user_id
        ORDER BY a.log_id DESC
    ''')
    logs = cursor.fetchall()
    conn.close()
    
    return render_template('admin_audit.html', logs=logs, is_valid=is_valid, message=message)

@app.route('/admin/unlock/<int:file_id>')
def admin_unlock(file_id):
    if 'user_id' not in session or session.get('role') != 'Admin':
        return redirect(url_for('login'))
        
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Reset the lockout flags and attempt counters
    cursor.execute('''
        UPDATE files 
        SET failed_decryption_attempts = 0, requires_admin = 0 
        WHERE file_id = ?
    ''', (file_id,))
    conn.commit()
    
    log_audit_event(session['user_id'], f"ADMIN_UNLOCKED_FILE_ID: {file_id}", "SUCCESS")
    conn.close()
    
    flash("Security override successful. File access restored to the original accountant.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/setup-2fa')
def setup_2fa():
    if 'setup_2fa_user' not in session:
        return redirect(url_for('login'))
        
    username = session['setup_2fa_user']
    secret = session['setup_2fa_secret']
    
    # Generate the standard Google Authenticator URI
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureFile Vault")
    
    # Create the QR Code image in memory
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_code_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    session.clear() # Clear setup session so they are forced to log in normally
    return render_template('setup_2fa.html', qr_code=qr_code_b64, secret=secret)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, password_hash, role, failed_attempts, is_locked FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            user_id, password_hash, role, failed_attempts, is_locked = user

            if is_locked:
                flash("Account locked. Please contact an Administrator.", "danger")
                conn.close()
                return render_template('login.html')

            if check_password_hash(password_hash, password):
                # PHASE 1 SUCCESS: Password is correct, but DO NOT log them in fully yet.
                # Hold their credentials in a temporary "pending" state.
                session['pending_user_id'] = user_id
                session['pending_username'] = username
                session['pending_role'] = role
                
                conn.close()
                return redirect(url_for('verify_2fa'))
            else:
                failed_attempts += 1
                is_locked_now = 1 if failed_attempts >= 3 else 0
                cursor.execute("UPDATE users SET failed_attempts = ?, is_locked = ? WHERE user_id = ?", (failed_attempts, is_locked_now, user_id))
                conn.commit()
                flash(f"Invalid credentials. Attempt {failed_attempts} of 3.", "warning" if not is_locked_now else "danger")
        else:
            flash("Invalid credentials.", "danger")
            
        conn.close()
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    # If they didn't pass the password check first, kick them out
    if 'pending_user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        otp_attempt = request.form.get('otp_code')
        user_id = session['pending_user_id']
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT totp_secret FROM users WHERE user_id = ?", (user_id,))
        secret = cursor.fetchone()[0]
        conn.close()
        
        # Verify the 6-digit Google Authenticator code
        totp = pyotp.TOTP(secret)
        if totp.verify(otp_attempt):
            # PHASE 2 SUCCESS: Fully log the user in
            session['user_id'] = session.pop('pending_user_id')
            session['username'] = session.pop('pending_username')
            session['role'] = session.pop('pending_role')
            
            log_audit_event(session['user_id'], "LOGIN_MFA", "SUCCESS")
            
            if session['role'] == 'Admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid Authenticator code. Please try again.", "danger")
            
    return render_template('verify_2fa.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    # CRITICAL FIX: Instantly redirect admins to their specific oversight panel
    if session.get('role') == 'Admin':
        return redirect(url_for('admin_dashboard'))
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Fetch files owned by the logged-in user
    cursor.execute('''
        SELECT file_id, filename, requires_admin, failed_decryption_attempts 
        FROM files WHERE owner_id = ?
    ''', (session['user_id'],))
    
    user_files = cursor.fetchall()
    conn.close()
    
    return render_template('dashboard.html', files=user_files)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    # Kick out anyone who isn't logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file selected.", "danger")
            return redirect(request.url)
        
        file = request.files['file']
        password = request.form.get('encryption_password')

        if file.filename == '' or not password:
            flash("Both a file and a secure password are required.", "danger")
            return redirect(request.url)

        # 1. Grab the file and read its data
        filename = secure_filename(file.filename)
        file_data = file.read()

        # 2. Generate the SHA-256 integrity hash for tamper detection[cite: 1]
        integrity_hash = hashlib.sha256(file_data).hexdigest()

        # 3. Turn the user's password into a 256-bit AES key[cite: 1]
        encryption_key = hashlib.sha256(password.encode()).digest()

        # 4. Encrypt the file data[cite: 1]
        encrypted_data = encrypt_file_data(file_data, encryption_key)

        # 5. Save the encrypted .enc file to our vault folder
        storage_path = os.path.join('vault', f"{filename}.enc")
        with open(storage_path, 'wb') as f:
            f.write(encrypted_data)

        # 6. Save the file details to the database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Note: If this throws an error, we might need to update your 'files' table schema!
        cursor.execute('''
            INSERT INTO files (owner_id, filename, storage_path, integrity_hash, requires_admin)
            VALUES (?, ?, ?, ?, 0)
        ''', (session['user_id'], filename, storage_path, integrity_hash))
        
        conn.commit()
        conn.close()

        # 7. Record the event in the audit log[cite: 1]
        log_audit_event(session['user_id'], f"ENCRYPT_FILE: {filename}", "SUCCESS")

        flash(f"File '{filename}' has been successfully encrypted and stored.", "success")
        return redirect(url_for('dashboard'))

    return render_template('upload.html')

@app.route('/decrypt/<int:file_id>', methods=['GET', 'POST'])
def decrypt_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Added integrity_hash to the SELECT statement
    cursor.execute('''
        SELECT filename, storage_path, requires_admin, failed_decryption_attempts, integrity_hash 
        FROM files WHERE file_id = ? AND owner_id = ?
    ''', (file_id, session['user_id']))
    file_record = cursor.fetchone()

    if not file_record:
        flash("File not found or unauthorized.", "danger")
        conn.close()
        return redirect(url_for('dashboard'))

    filename, storage_path, requires_admin, failed_attempts, original_hash = file_record

    if requires_admin:
        flash("This file is LOCKED due to 3 failed attempts. Contact Admin.", "danger")
        conn.close()
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        password = request.form.get('decryption_password')
        
        with open(storage_path, 'rb') as f:
            encrypted_data = f.read()

        decryption_key = hashlib.sha256(password.encode()).digest()

        try:
            # 1. AES-256-GCM Decryption
            decrypted_data = decrypt_file_data(encrypted_data, decryption_key)
            
            # 2. SHA-256 Integrity Verification (Tamper Detection Check)
            current_hash = hashlib.sha256(decrypted_data).hexdigest()
            
            if current_hash != original_hash:
                # TAMPER DETECTED: Hashes do not match
                log_audit_event(session['user_id'], f"TAMPER_DETECTED: {filename}", "CRITICAL_BREACH")
                cursor.execute("UPDATE files SET requires_admin = 1 WHERE file_id = ?", (file_id,))
                conn.commit()
                flash("CRITICAL ALERT: File integrity compromised. Unauthorized modifications detected via SHA-256 mismatch. File locked.", "danger")
                conn.close()
                return redirect(url_for('dashboard'))

            # SUCCESS: Reset attempts and serve file
            cursor.execute("UPDATE files SET failed_decryption_attempts = 0 WHERE file_id = ?", (file_id,))
            conn.commit()
            log_audit_event(session['user_id'], f"DECRYPT_AND_VERIFY: {filename}", "SUCCESS")
            conn.close()

            return send_file(
                io.BytesIO(decrypted_data),
                as_attachment=True,
                download_name=f"VERIFIED_{filename}"
            )

        except ValueError:
            failed_attempts += 1
            is_locked = 1 if failed_attempts >= 3 else 0
            
            cursor.execute('''
                UPDATE files SET failed_decryption_attempts = ?, requires_admin = ? 
                WHERE file_id = ?
            ''', (failed_attempts, is_locked, file_id))
            conn.commit()
            
            if is_locked:
                log_audit_event(session['user_id'], f"FILE_LOCKED: {filename}", "LOCKED")
                flash("File has been securely LOCKED after 3 failed attempts.", "danger")
                conn.close()
                return redirect(url_for('dashboard'))
            else:
                log_audit_event(session['user_id'], f"DECRYPT_FAILED: {filename}", "FAILED")
                flash(f"Incorrect password or corrupted ciphertext. Attempt {failed_attempts} of 3.", "warning")

    conn.close()
    return render_template('decrypt.html', filename=filename)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_audit_event(session['user_id'], "LOGOUT", "SUCCESS")
    session.clear()
    flash("You have been securely logged out.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Ensure the 'vault' directory exists for storing the actual AES-encrypted files
    if not os.path.exists('vault'):
        os.makedirs('vault')
        print("Created 'vault' directory for encrypted files.")

    # Initialize the database tables
    init_db()
    print("SQLite database and tables initialized successfully.")

    # Run the Flask development server
    app.run(debug=True)