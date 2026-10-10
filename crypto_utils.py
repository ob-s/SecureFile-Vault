from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def generate_aes_key():
    """Generates a secure 256-bit (32-byte) key for AES-256-GCM."""
    return get_random_bytes(32)

def encrypt_file_data(data: bytes, key: bytes) -> bytes:
    """
    Encrypts file data using AES-256-GCM.
    Returns a single byte string containing the nonce, authentication tag, and ciphertext.
    """
    # Initialize AES in Galois/Counter Mode (GCM)
    cipher = AES.new(key, AES.MODE_GCM)
    
    # Encrypt the data and generate the cryptographic authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    # Prepend the 16-byte nonce and 16-byte tag to the ciphertext for storage
    return cipher.nonce + tag + ciphertext

def decrypt_file_data(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypts file data using AES-256-GCM and verifies its cryptographic integrity.
    Raises ValueError if the authentication tag is invalid (tamper detected).
    """
    # Extract the components based on the exact byte lengths used during encryption
    nonce = encrypted_data[:16]      # First 16 bytes
    tag = encrypted_data[16:32]      # Next 16 bytes
    ciphertext = encrypted_data[32:] # The remaining bytes are the actual ciphertext
    
    # Re-initialize AES in GCM mode using the specific nonce used during encryption
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    try:
        # Decrypt the ciphertext and verify the authentication tag
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data
    except ValueError as e:
        # PyCryptodome raises a ValueError if the tag doesn't match the ciphertext.
        # This means the file was tampered with, corrupted, or the wrong key was used.
        raise ValueError("Cryptographic verification failed: Data integrity compromised.") from e