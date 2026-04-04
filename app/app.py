"""
Simple Web Application for File Encryption & Decryption
Upload files to encrypt, download encrypted files to decrypt
"""

from flask import Flask, render_template, request, send_file, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max

# Create uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Generate keys on startup
def generate_keys():
    if not os.path.exists('private.pem') or not os.path.exists('public.pem'):
        print("Generating RSA keys...")
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        with open('private.pem', 'wb') as f:
            f.write(private_key)
        with open('public.pem', 'wb') as f:
            f.write(public_key)
        print("Keys generated successfully!")

# Encryption function
def encrypt_file_data(file_data):
    public_key = RSA.import_key(open('public.pem').read())
    session_key = get_random_bytes(16)
    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)
    
    return enc_session_key + cipher_aes.nonce + tag + ciphertext

# Decryption function
def decrypt_file_data(encrypted_data):
    private_key = RSA.import_key(open('private.pem').read())
    
    enc_session_key = encrypted_data[:private_key.size_in_bytes()]
    nonce = encrypted_data[private_key.size_in_bytes():private_key.size_in_bytes() + 16]
    tag = encrypted_data[private_key.size_in_bytes() + 16:private_key.size_in_bytes() + 32]
    ciphertext = encrypted_data[private_key.size_in_bytes() + 32:]
    
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    return data

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read file data
        file_data = file.read()
        
        # Encrypt
        encrypted_data = encrypt_file_data(file_data)
        
        # Save encrypted file
        filename = secure_filename(file.filename)
        encrypted_filename = f"{filename}.encrypted"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        
        with open(filepath, 'wb') as f:
            f.write(encrypted_data)
        
        return jsonify({
            'success': True,
            'message': f'File encrypted successfully!',
            'filename': encrypted_filename,
            'download_url': f'/download_encrypted/{encrypted_filename}'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download_encrypted/<filename>')
def download_encrypted(filename):
    """Download encrypted file"""
    try:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404
        
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename
        )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read encrypted file data
        encrypted_data = file.read()
        
        # Decrypt
        decrypted_data = decrypt_file_data(encrypted_data)
        
        # Save decrypted file
        filename = secure_filename(file.filename)
        if filename.endswith('.encrypted'):
            filename = filename[:-10]  # Remove .encrypted extension
        
        decrypted_filename = f"decrypted_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
        
        with open(filepath, 'wb') as f:
            f.write(decrypted_data)
        
        return jsonify({
            'success': True,
            'message': 'File decrypted successfully!',
            'filename': decrypted_filename,
            'download_url': f'/download_decrypted/{decrypted_filename}'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download_decrypted/<filename>')
def download_decrypted(filename):
    """Download decrypted file"""
    try:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404
        
        # Remove 'decrypted_' prefix for download name
        download_name = filename.replace('decrypted_', '')
        
        return send_file(
            filepath,
            as_attachment=True,
            download_name=download_name
        )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/clear_uploads', methods=['POST'])
def clear_uploads():
    """Remove all files from uploads folder"""
    try:
        removed_count = 0

        for name in os.listdir(app.config['UPLOAD_FOLDER']):
            path = os.path.join(app.config['UPLOAD_FOLDER'], name)
            if os.path.isfile(path):
                os.remove(path)
                removed_count += 1

        return jsonify({
            'success': True,
            'message': f'Cleared {removed_count} file(s) from uploads folder.'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    generate_keys()
    app.run(host="0.0.0.0", port=5000)
