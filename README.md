# 🛡️ SecureFile Analytics & Vault
**A Secure File Encryption System for Accountants with Blockchain-Based Audit Logging and Tamper Detection**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Flask](https://img.shields.io/badge/Framework-Flask-black?logo=flask)
![Encryption](https://img.shields.io/badge/Cryptography-AES--256--GCM-success)
![Integrity](https://img.shields.io/badge/Integrity-SHA--256-brightgreen)
![Audit](https://img.shields.io/badge/Audit_Ledger-Blockchain_Hash--Chain-warning)
![MFA](https://img.shields.io/badge/Zero--Trust-TOTP_2FA-informational)

## 📖 Overview
**SecureFile Vault** is a zero-trust, enterprise-grade web application engineered specifically for accounting professionals to protect sensitive financial ledgers, tax documents, and invoices at rest. 

Traditional file storage systems are vulnerable to unauthorized modifications, credential theft, and retroactive log erasure by malicious insiders or external attackers. SecureFile Vault solves this by combining **AES-256-GCM authenticated encryption**, **SHA-256 digital fingerprinting** for automated tamper lockouts, **Google Authenticator Multi-Factor Authentication (MFA)**, strict **Role-Based Access Control (RBAC)**, and an **Immutable Private Blockchain Audit Ledger** that mathematically verifies the integrity of every system event.

---

## ✨ Core Security Architecture & Features

### 1. 🔐 Military-Grade File Encryption (AES-256-GCM)
* All uploaded financial documents are encrypted in memory using **AES-256 in Galois/Counter Mode (GCM)** before being written to the local `/vault` directory as `.enc` ciphertext files.
* Cryptographic keys are dynamically derived using SHA-256 from the accountant's file-specific password—ensuring **Zero-Trust privacy**. Even System Administrators cannot decrypt an accountant's private files.

### 2. 🧬 Automated Tamper Detection & Lockout (SHA-256)
* **Digital Fingerprinting:** Upon upload, the raw file bytes are hashed via **SHA-256** and stored alongside the file record.
* **Active Verification Trap:** During decryption, the system recalculates the SHA-256 hash of the decrypted payload and compares it against the original database fingerprint (`current_hash == original_hash`).
* **Automated Quarantine:** If a single byte has been modified behind the scenes (or if 3 consecutive decryption attempts fail), the system aborts the download, locks the file (`requires_admin = 1`), and dispatches a `CRITICAL_BREACH` alert to the Administrator Oversight Panel.

### 3. ⛓️ Immutable Blockchain-Based Audit Logging
* **Cryptographic Hash-Chaining:** Unlike standard database logs that can be silently deleted or altered by a rogue insider, every event (`LOGIN_MFA`, `ENCRYPT_FILE`, `DECRYPT_AND_VERIFY`, `TAMPER_DETECTED`, `ADMIN_PASSWORD_RESET`) is recorded as a sequential block.
* **Mathematical Immutability:** Each block computes its `block_hash` using the formula:
  `SHA256(user_id | action | timestamp | status | previous_hash)`
* **Live Chain Verification:** Whenever the Administrator opens the Audit Ledger, the system recalculates the entire chain starting from **Block #1 (Genesis Block)**. Any retroactive modification to the SQLite database breaks the mathematical chain and triggers an immediate red `TAMPER DETECTED` alert.
* **Compliance Archiving:** Administrators can export filtered audit trails (**Past 1 Week**, **Past 2 Weeks**, or **Full History**) directly to `.csv` spreadsheets.
## ⛓️ Deep Dive: Private Blockchain Audit Architecture

### 1. Architectural Classification
SecureFile Vault implements a **Private, Permissioned, Cryptographic Hash-Chain Ledger** (an Immutable Append-Only Audit Log). 

Unlike public, decentralized blockchains (such as Bitcoin or Ethereum) that rely on computationally expensive Proof-of-Work (PoW) mining, cryptocurrency gas fees, and public data broadcasting—which violate financial data privacy regulations—this system utilizes an **enterprise permissioned model**. The Flask application server acts as the authenticated authority node, utilizing the core cryptographic data structure of blockchain technology (sequential SHA-256 hash pointers) to guarantee forensic log immutability with zero latency.

### 2. Anatomy of an Audit Block
Every security-critical event (`LOGIN_MFA`, `ENCRYPT_FILE`, `DECRYPT_AND_VERIFY`, `TAMPER_DETECTED`, `ADMIN_PASSWORD_RESET`, `EXPORT_AUDIT_LOGS`) is encapsulated into a structured block inside the `audit_logs` ledger containing:

| Field | Data Type | Description |
| :--- | :--- | :--- |
| **`log_id`** | `INTEGER` | The sequential block height/index (e.g., Block `#1`, `#2`, `#3`). |
| **`user_id`** | `INTEGER` | The authenticated actor performing the operation (`NULL` / `SYSTEM` for Genesis). |
| **`action`** | `TEXT` | Specific operation executed and target filename (e.g., `ENCRYPT_FILE: invoice.txt`). |
| **`timestamp`** | `TEXT` | Exact ISO-formatted timestamp down to the second (`YYYY-MM-DD HH:MM:SS`). |
| **`status`** | `TEXT` | Execution outcome (`SUCCESS`, `FAILED`, `LOCKED`, `CRITICAL_BREACH`). |
| **`previous_hash`** | `TEXT (64-char)` | The cryptographic SHA-256 `block_hash` of the immediately preceding block ($Block_{n-1}$). |
| **`block_hash`** | `TEXT (64-char)` | The digital seal of the current block ($Block_n$), derived from its payload and `previous_hash`. |

### 3. Cryptographic Chaining & Mathematical Formula
To lock each block into the historical chain, the system constructs a deterministic string payload combining the current event metadata with the hash of the preceding block:

$$\text{BlockHash}_n = \text{SHA256}(\text{UserID}_n \parallel \text{Action}_n \parallel \text{Timestamp}_n \parallel \text{Status}_n \parallel \text{BlockHash}_{n-1})$$

1. **The Genesis Block (Block #1):** The chain is anchored by an automated `SYSTEM_INIT` Genesis Block whose `previous_hash` is hardcoded to a 64-character zero string (`0000000000000000000000000000000000000000000000000000000000000000`).
2. **Sequential Linking:** When Block #2 is created, it fetches Block #1's `block_hash` and embeds it into its own calculation. Block #3 embeds Block #2's hash, creating an unbroken mathematical dependency from the first system boot to the latest user action.

```text
+---------------------------------------+       +---------------------------------------+
|              BLOCK #1                 |       |              BLOCK #2                 |
|             (Genesis)                 |       |           (User Event)                |
+---------------------------------------+       +---------------------------------------+
| Actor:      SYSTEM                    |       | Actor:      administrator             |
| Action:     SYSTEM_INIT               |       | Action:     LOGIN_MFA                 |
| Status:     SUCCESS                   |       | Status:     SUCCESS                   |
| Prev Hash:  00000000000000000000...   |       | Prev Hash:  2725e73e352cc99fbd8a...   | <--+
| Block Hash: 2725e73e352cc99fbd8a...   | ----> | Block Hash: 9a8b7c6d5e4f3a2b1c0d...   |    |
+---------------------------------------+       +---------------------------------------+    |
                                                                (Cryptographic Link) --------+

### 4. 📱 Mandatory Zero-Trust MFA (TOTP / Google Authenticator)
* Every profile is provisioned with a unique Base32 secret (`pyotp`) and scannable QR code (`qrcode`) upon registration.
* Authentication enforces a strict two-stage check: Password Verification $\rightarrow$ 6-Digit Time-Based One-Time Password (TOTP) hardware verification.

### 5. 👥 Role-Based Access Control (RBAC) & Admin Oversight
* **Accountant Role:** Access to personal encrypted financial ledgers, file upload/encryption, verified decryption, and vault analytics.
* **Administrator Role:** Dedicated dark-themed **System Administrator Oversight** dashboard featuring global locked-file overrides, user lockout resets, administrative password resets, and the live Blockchain Audit Ledger.

---

## 🛠️ Technology Stack
* **Backend:** Python 3, Flask
* **Cryptography:** `cryptography` (AES-256-GCM), `hashlib` (SHA-256), `werkzeug.security` (PBKDF2/Scrypt password hashing)
* **Multi-Factor Authentication:** `pyotp` (RFC 6238 TOTP), `qrcode`, `Pillow`
* **Database:** SQLite3 (`vault.db` relational storage + append-only blockchain ledger table)
* **Frontend:** HTML5, Bootstrap 5.3, Bootstrap Icons, Chart.js

---

## 📂 Project Structure
```text
SecureFile-Vault/
│
├── app.py                         # Main Flask application, RBAC routes, & Blockchain verifier
├── crypto_utils.py                # AES-256-GCM encryption and decryption engine
├── seed_users.py                  # Database seeder for default Admin and Accountant test accounts
├── upgrade_db.py                  # Schema migration for TOTP MFA secrets
├── upgrade_blockchain_db.py       # Schema migration & Genesis Block initializer
├── fix_blockchain.py              # Utility to verify and repair cryptographic hash chains
├── show_admin_mfa.py              # Utility to display QR Code / TOTP secret for seeded accounts
├── simulate_insider_threat.py     # Red-Team simulation script to test SHA-256 tamper detection
│
├── vault/                         # Protected directory storing AES-256 encrypted (.enc) files
├── templates/
│   ├── index.html                 # Landing page
│   ├── register.html              # Split-screen glassmorphic Accountant registration
│   ├── setup_2fa.html             # QR Code & Manual Key TOTP provisioning screen
│   ├── login.html                 # Step 1 Authentication (Credentials)
│   ├── verify_2fa.html            # Step 2 Authentication (6-Digit Google Authenticator OTP)
│   ├── dashboard.html             # Accountant workspace, analytics, and file vault
│   ├── upload.html                # AES-256-GCM file encryption interface
│   ├── decrypt.html               # File decryption & SHA-256 verification prompt
│   ├── admin_dashboard.html       # Admin Oversight: Locked file overrides & User password resets
│   └── admin_audit.html           # Admin Blockchain Audit Ledger & CSV compliance exporter
│
└── README.md                      # Project documentation