import sqlite3
import pyotp
import qrcode

def show_mfa_code():
    conn = sqlite3.connect('vault.db')
    cursor = conn.cursor()
    
    # Fetch the administrator's secret
    cursor.execute("SELECT username, totp_secret FROM users WHERE username = 'administrator'")
    admin = cursor.fetchone()
    conn.close()
    
    if admin and admin[1]:
        username, secret = admin
        print("\n=== ADMINISTRATOR MFA RECOVERY ===")
        print(f"Manual Setup Key: {secret}")
        print("==================================\n")
        
        # Generate and open the QR code image
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureFile Vault")
        img = qrcode.make(totp_uri)
        
        print("Opening QR code... Please scan it with Google Authenticator.")
        img.show()  # This will open the QR code image on your computer
    else:
        print("Administrator account or MFA secret not found.")

if __name__ == '__main__':
    show_mfa_code()