from flask import Flask, request, jsonify
import sqlite3
import hashlib
import re
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import logging
import argparse

app = Flask(__name__)

logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
DATABASE = 'storage.db'

def initialize_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY,
                  password_hash TEXT,
                  salt TEXT,
                  public_key TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (file_id INTEGER PRIMARY KEY,
                  filename TEXT,
                  owner TEXT,
                  encrypted_content TEXT,
                  encrypted_key TEXT,
                  FOREIGN KEY(owner) REFERENCES users(username))''')
    c.execute('''CREATE TABLE IF NOT EXISTS shares
                 (share_id INTEGER PRIMARY KEY,
                  file_id INTEGER,
                  owner TEXT,
                  shared_with TEXT,
                  encrypted_key TEXT,
                  FOREIGN KEY(file_id) REFERENCES files(file_id),
                  FOREIGN KEY(owner) REFERENCES users(username),
                  FOREIGN KEY(shared_with) REFERENCES users(username))''')
    conn.commit()
    conn.close()

initialize_db()

def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    salt = bytes.fromhex(data.get('salt'))
    public_key = data.get('public_key')
    if not all([username, password, salt, public_key]):
        return jsonify({
            'error': 'missing_fields',
            'error_description': 'Please enter all required fields (username, password, etc.)'
        }), 400
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', (username,))
    if c.fetchone():
        conn.close()
        return jsonify({
            'error': 'username_exists',
            'error_description': 'This username is already taken. Please choose another.'
        }), 400
    
    c.execute('INSERT INTO users VALUES (?, ?, ?, ?)', (username, password, salt.hex(), public_key))
    conn.commit()
    conn.close()
    logging.info(f"New user registered: {username}")
    return jsonify({'message': 'User registered successfully'}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({
            'error': 'missing_fields',
            'error_description': 'Please enter username and password'
        }), 400
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', (username,))
    user = c.fetchone()
    conn.close()
    
    if not user or hash_password(password, bytes.fromhex(user[2])) != user[1].encode():
        return jsonify({
            'error': 'invalid_credentials',
            'error_description': 'Incorrect username or password'
        }), 401
    
    logging.info(f"User logged in: {username}")
    return jsonify({'message': 'Login successful'}), 200

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    username = data.get('username')
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    if not all([username, old_password, new_password]):
        return jsonify({
            'error': 'missing_fields',
            'error_description': 'Please enter username, current password, and new password'
        }), 400
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', (username,))
    user = c.fetchone()
    if not user:
        conn.close()
        return jsonify({
            'error': 'user_not_found',
            'error_description': 'User not found'
        }), 404
    
    # Verify old password
    if hash_password(old_password, bytes.fromhex(user[2])) != user[1].encode():
        conn.close()
        return jsonify({
            'error': 'incorrect_old_password',
            'error_description': 'Current password is incorrect'
        }), 401
    
    # Generate new salt and hash
    new_salt = os.urandom(16)
    new_password_hash = hash_password(new_password, new_salt)
    
    # Update password and salt
    c.execute('UPDATE users SET password_hash=?, salt=? WHERE username=?',
              (new_password_hash.decode(), new_salt.hex(), username))
    conn.commit()
    conn.close()
    logging.info(f"Password reset for user: {username}")
    return jsonify({'message': 'Password reset successfully'}), 200

@app.route('/upload', methods=['POST'])
def upload_file():
    data = request.json
    username = data.get('username')
    filename = data.get('filename')
    encrypted_content = data.get('encrypted_file')
    encrypted_key = data.get('encrypted_key')
    if not all([username, filename, encrypted_content, encrypted_key]):
        return jsonify({
            'error': 'missing_fields',
            'error_description': 'Please provide file name and content'
        }), 400
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT public_key FROM users WHERE username=?', (username,))
    public_key_pem = c.fetchone()
    if not public_key_pem:
        conn.close()
        return jsonify({
            'error': 'user_not_found',
            'error_description': 'User not found. Please register first.'
        }), 404
    
    public_key = serialization.load_pem_public_key(public_key_pem[0].encode())
    
    fernet_key = base64.b64decode(encrypted_key)
    encrypted_key_for_owner = public_key.encrypt(
        fernet_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    c.execute('INSERT INTO files (filename, owner, encrypted_content, encrypted_key) VALUES (?, ?, ?, ?)',
              (filename, username, encrypted_content, base64.b64encode(encrypted_key_for_owner).decode()))
    file_id = c.lastrowid
    conn.commit()
    conn.close()
    logging.info(f"File uploaded by user: {username}, filename: {filename}")
    return jsonify({'message': 'File uploaded successfully', 'file_id': file_id}), 200

@app.route('/download', methods=['POST'])
def download_file():
    data = request.json
    username = data.get('username')
    file_id = data.get('file_id')
    if not username or not file_id:
        return jsonify({
            'error': 'missing_fields',
            'error_description': 'Please enter file ID'
        }), 400
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''SELECT filename, encrypted_content, encrypted_key 
                 FROM files 
                 WHERE file_id=? AND owner=?''', (file_id, username))
    result = c.fetchone()
    encrypted_key = None
    if result:
        encrypted_key = result[2]
    else:
        c.execute('''SELECT f.filename, f.encrypted_content, s.encrypted_key 
                     FROM files f
                     JOIN shares s ON f.file_id = s.file_id
                     WHERE s.file_id=? AND s.shared_with=?''', (file_id, username))
        result = c.fetchone()
        if result:
            encrypted_key = result[2]
    
    conn.close()
    if not result:
        return jsonify({
            'error': 'file_not_found_or_unauthorized',
            'error_description': 'File not found or you lack access permission'
        }), 404
    
    filename, encrypted_content = result[0], result[1]
    return jsonify({
        'message': 'File downloaded successfully',
        'filename': filename,
        'encrypted_content': encrypted_content,
        'encrypted_key': encrypted_key
    }), 200

@app.route('/share', methods=['POST'])
def share_file():
    data = request.json
    username = data.get('username')
    file_id = data.get('file_id')
    shared_with = data.get('shared_with')
    encrypted_key = data.get('encrypted_key')
    if not all([username, file_id, shared_with, encrypted_key]):
        return jsonify({
            'error': 'missing_fields',
            'error_description': 'Please enter file ID and target user'
        }), 400
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM files WHERE file_id=? AND owner=?', (file_id, username))
    if not c.fetchone():
        conn.close()
        return jsonify({
            'error': 'file_not_found_or_not_owner',
            'error_description': 'File not found or you are not the owner'
        }), 403
    
    c.execute('SELECT * FROM users WHERE username=?', (shared_with,))
    if not c.fetchone():
        conn.close()
        return jsonify({
            'error': 'target_user_not_found',
            'error_description': 'Target user does not exist'
        }), 404
    
    c.execute('SELECT * FROM shares WHERE file_id=? AND owner=? AND shared_with=?',
              (file_id, username, shared_with))
    if c.fetchone():
        conn.close()
        return jsonify({
            'error': 'already_shared',
            'error_description': 'File is already shared with this user'
        }), 400
    
    c.execute('INSERT INTO shares (file_id, owner, shared_with, encrypted_key) VALUES (?, ?, ?, ?)',
              (file_id, username, shared_with, encrypted_key))
    conn.commit()
    conn.close()
    logging.info(f"File {file_id} shared by {username} with {shared_with}")
    return jsonify({'message': 'File shared successfully'}), 200

@app.route('/get_public_key', methods=['POST'])
def get_public_key():
    data = request.json
    username = data.get('username')
    if not username:
        return jsonify({
            'error': 'missing_username',
            'error_description': 'Please provide username'
        }), 400
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT public_key FROM users WHERE username=?', (username,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return jsonify({
            'error': 'user_not_found',
            'error_description': 'User not found'
        }), 404
    
    return jsonify({'public_key': result[0]}), 200

@app.route('/list_files', methods=['POST'])
def list_files():
    data = request.json
    username = data.get('username')
    if not username:
        return jsonify({
            'error': 'missing_username',
            'error_description': 'Please provide username'
        }), 400
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT file_id, filename FROM files WHERE owner=?', (username,))
    owned_files = [{'file_id': row[0], 'filename': row[1]} for row in c.fetchall()]
    c.execute('SELECT f.file_id, f.filename FROM files f JOIN shares s ON f.file_id = s.file_id WHERE s.shared_with=?', (username,))
    shared_files = [{'file_id': row[0], 'filename': row[1]} for row in c.fetchall()]
    conn.close()
    
    logging.info(f"Listed files for user: {username}")
    return jsonify({'owned_files': owned_files, 'shared_files': shared_files}), 200

@app.route('/delete_file', methods=['POST'])
def delete_file():
    data = request.json
    username = data.get('username')
    file_id = data.get('file_id')
    if not username or not file_id:
        return jsonify({
            'error': 'missing_fields',
            'error_description': 'Please enter file ID'
        }), 400
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM files WHERE file_id=? AND owner=?', (file_id, username))
    if not c.fetchone():
        conn.close()
        return jsonify({
            'error': 'file_not_found_or_not_owner',
            'error_description': 'File not found or you are not the owner'
        }), 403
    
    c.execute('DELETE FROM shares WHERE file_id=?', (file_id,))
    c.execute('DELETE FROM files WHERE file_id=?', (file_id,))
    conn.commit()
    conn.close()
    logging.info(f"File {file_id} deleted by {username}")
    return jsonify({'message': 'File deleted successfully'}), 200

@app.route('/revoke_share', methods=['POST'])
def revoke_share():
    data = request.json
    username = data.get('username')
    file_id = data.get('file_id')
    shared_with = data.get('shared_with')
    if not all([username, file_id, shared_with]):
        return jsonify({
            'error': 'missing_fields',
            'error_description': 'Please enter file ID and target user'
        }), 400
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('DELETE FROM shares WHERE file_id=? AND owner=? AND shared_with=?', (file_id, username, shared_with))
    if c.rowcount == 0:
        conn.close()
        return jsonify({
            'error': 'share_not_found',
            'error_description': 'No such share exists or you are not the owner'
        }), 403
    
    conn.commit()
    conn.close()
    logging.info(f"Share revoked for file {file_id} by {username} from {shared_with}")
    return jsonify({'message': 'Share revoked successfully'}), 200

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Secure Online Storage Server')
    parser.add_argument('--host', type=str, default='127.0.0.1',
                        help='Hostname or IP address to run the server on')
    parser.add_argument('--port', type=int, default=5000,
                        help='Port number to run the server on')
    args = parser.parse_args()
    print("Server listening on 127.0.0.1:5000")
    app.run(host=args.host, port=args.port)