from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def upload_file(file_path, user):
    # Read file
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Generate AES key and nonce
    aes_key = os.urandom(32)
    nonce = os.urandom(16)
    
    # Encrypt file
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    
    # Encrypt AES key with user's public key
    encrypted_aes_key = user.public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    # Send to server 
    send_to_server({
        'action': 'upload',
        'encrypted_data': encrypted_data,
        'nonce': nonce,
        'encrypted_key': encrypted_aes_key,
        'file_name': os.path.basename(file_path)
    })

def share_file(file_id, recipient_username):
    # Retrieve recipient's public key from server
    recipient_pub_key = get_pub_key(recipient_username)
    
    # Encrypt file key with recipient's public key
    encrypted_key = recipient_pub_key.encrypt(
        file_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    # Send to server to store in file_keys
    send_to_server({
        'action': 'share',
        'file_id': file_id,
        'recipient': recipient_username,
        'encrypted_key': encrypted_key
    })

def update_file(file_id, modified_blocks):
    # For each modified block, encrypt and send to server
    for block in modified_blocks:
        cipher = Cipher(algorithms.AES(file_key), modes.CTR(nonce + block.offset))
        encryptor = cipher.encryptor()
        encrypted_block = encryptor.update(block.data) + encryptor.finalize()
        
        send_to_server({
            'action': 'update_block',
            'file_id': file_id,
            'offset': block.offset,
            'encrypted_block': encrypted_block
        })

def log_action(user_id, action, details):
    conn = sqlite3.connect('storage.db')
    c = conn.cursor()
    c.execute('INSERT INTO logs (user_id, action, timestamp, details) VALUES (?, ?, datetime(), ?)',
              (user_id, action, details))
    conn.commit()
    conn.close()

def sanitize_filename(name):
    return name.replace('../', '').replace('/', '_')

# Example of parameterized query
def get_user(username):
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    return c.fetchone()