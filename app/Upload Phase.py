from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

def encrypt_file(file_path, public_key_path):
    with open(file_path, "rb") as f:
        data = f.read()

    recipient_key = RSA.import_key(open(public_key_path).read())
    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    with open("encrypted_cloud_data.bin", "wb") as f:
        [f.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
    print(f"File '{file_path}' encrypted for cloud storage.")

encrypt_file("sensitive_report.txt", "public.pem")