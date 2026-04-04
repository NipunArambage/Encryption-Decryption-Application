"""
Simple File Encryption & Decryption Project
Encrypts a text file and then decrypts it back to original
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os

#  STEP 1: Generate RSA Keys 
def generate_keys():
    print("\n[1] Generating RSA Keys...")
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    with open("private.pem", "wb") as f:
        f.write(private_key)
    with open("public.pem", "wb") as f:
        f.write(public_key)
    
    print("    ✓ RSA Keys generated successfully!")

#  STEP 2: Create Sample Text File 
def create_sample_file():
    print("\n[2] Creating sample text file...")
    sample_text = """This is a confidential document that needs to be encrypted.
It contains sensitive information that should be protected.
The project will encrypt this file and then decrypt it back to original format."""
    
    with open("original_document.txt", "w") as f:
        f.write(sample_text)
    
    print("    ✓ Sample file 'original_document.txt' created!")

# STEP 3: Encrypt File
def encrypt_file(file_path, public_key_path):
    print(f"\n[3] Encrypting '{file_path}'...")
    
    # Read the file
    with open(file_path, "rb") as f:
        data = f.read()
    
    # Load public key
    public_key = RSA.import_key(open(public_key_path).read())
    
    # Generate session key
    session_key = get_random_bytes(16)
    
    # Encrypt session key with RSA
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    
    # Encrypt data with AES
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    
    # Save encrypted file
    with open("encrypted_file.bin", "wb") as f:
        f.write(enc_session_key + cipher_aes.nonce + tag + ciphertext)
    
    print("    ✓ File encrypted successfully!")
    print("    → Saved as: 'encrypted_file.bin'")

# STEP 4: Decrypt File
def decrypt_file(encrypted_file_path, private_key_path):
    print(f"\n[4] Decrypting '{encrypted_file_path}'...")
    
    # Load private key
    private_key = RSA.import_key(open(private_key_path).read())
    
    # Read encrypted file
    with open(encrypted_file_path, "rb") as f:
        enc_session_key = f.read(private_key.size_in_bytes())
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
    
    # Decrypt session key with RSA
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    
    # Decrypt data with AES
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    # Save decrypted file
    with open("decrypted_document.txt", "wb") as f:
        f.write(data)
    
    print("    ✓ File decrypted successfully!")
    print("    → Saved as: 'decrypted_document.txt'")
    print(f"    → Content:\n{data.decode()}\n")

# 
#  MAIN EXECUTION
if __name__ == "__main__":
    print("=" * 60)
    print("  FILE ENCRYPTION & DECRYPTION PROJECT")
    print("=" * 60)
    
    # Run all steps
    generate_keys()
    create_sample_file()
    encrypt_file("original_document.txt", "public.pem")
    decrypt_file("encrypted_file.bin", "private.pem")
    
    print("=" * 60)
    print("  ✓ PROJECT COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    print("\nGenerated Files:")
    print("  • private.pem           - Private encryption key")
    print("  • public.pem            - Public encryption key")
    print("  • original_document.txt - Original text file")
    print("  • encrypted_file.bin    - Encrypted binary file")
    print("  • decrypted_document.txt - Decrypted text file (matches original)")
    print("\n")
