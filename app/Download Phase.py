from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

def decrypt_file(encrypted_file_path, private_key_path):
    private_key = RSA.import_key(open(private_key_path).read())

    with open(encrypted_file_path, "rb") as f:
        enc_session_key = f.read(private_key.size_in_bytes())
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    with open("decrypted_file.txt", "wb") as f:
        f.write(data)
    print("Decryption successful. Integrity verified.")

decrypt_file("encrypted_cloud_data.bin", "private.pem")