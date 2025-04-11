from flask import Flask, request, jsonify
import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import logging
import argparse

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration
DATABASE = 'storage.db'

# Initialize database tables if they don't exist
def initialize_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # User table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username text PRIMARY KEY,
                  password_hash text,
                  salt text)''')
    
    # File table
    # Check if files table exists and has all required columns
    c.execute("PRAGMA table_info(files)")
    columns = [column[1] for column in c.fetchall()]
    
    # Required columns
    required_columns = ['file_id', 'filename', 'owner', 'encrypted_key', 'encrypted_content']
    
    # If any required column is missing, drop the table and recreate it
    if not all(col in columns for col in required_columns):
        c.execute("DROP TABLE IF EXISTS files")
        c.execute('''CREATE TABLE files
                     (file_id integer PRIMARY KEY,
                      filename text,
                      owner text,
                      encrypted_key text,
                      encrypted_content blob,
                      FOREIGN KEY(owner) REFERENCES users(username))''')
    else:
        # Ensure all columns exist by creating if necessary
        c.execute('''ALTER TABLE files 
                     ADD COLUMN IF NOT EXISTS encrypted_content blob''')
    
    # Share table
    c.execute('''CREATE TABLE IF NOT EXISTS shares
                 (share_id integer PRIMARY KEY,
                  file_id integer,
                  owner text,
                  shared_with text,
                  FOREIGN KEY(file_id) REFERENCES files(file_id),
                  FOREIGN KEY(owner) REFERENCES users(username),
                  FOREIGN KEY(shared_with) REFERENCES users(username))''')
    
    conn.commit()
    conn.close()

# Initialize database
initialize_db()

# Generate password hash
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
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    # Generate random salt
    salt = os.urandom(16)
    
    # Hash the password
    password_hash = hash_password(password, salt)
    
    # Check if username already exists
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', (username,))
    if c.fetchone() is not None:
        return jsonify({'error': 'Username already exists'}), 400
    
    # Insert new user
    c.execute('INSERT INTO users VALUES (?, ?, ?)',
              (username, password_hash.decode(), salt.hex()))
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
        return jsonify({'error': 'Username and password are required'}), 400
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', (username,))
    user = c.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401
    
    # Verify password
    salt = bytes.fromhex(user[2])
    password_hash = hash_password(password, salt)
    if password_hash != user[1].encode():
        return jsonify({'error': 'Invalid username or password'}), 401
    
    logging.info(f"User logged in: {username}")
    return jsonify({'message': 'Login successful'}), 200

@app.route('/upload', methods=['POST'])
def upload_file():
    data = request.json
    username = data.get('username')
    filename = data.get('filename')
    encrypted_content = data.get('encrypted_content')
    
    if not username or not filename or not encrypted_content:
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Generate a random key for file encryption
    key = Fernet.generate_key()
    f = Fernet(key)
    
    # Store the encrypted file
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''INSERT INTO files (filename, owner, encrypted_key, encrypted_content) 
                 VALUES (?, ?, ?, ?)''',
              (filename, username, key.decode(), encrypted_content))
    conn.commit()
    conn.close()
    
    logging.info(f"File uploaded by user: {username}, filename: {filename}")
    return jsonify({'message': 'File uploaded successfully'}), 200

@app.route('/download', methods=['POST'])
def download_file():
    data = request.json
    username = data.get('username')
    file_id = data.get('file_id')
    
    if not username or not file_id:
        return jsonify({'error': 'Missing required fields'}), 400
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''SELECT encrypted_key, encrypted_content 
                 FROM files 
                 WHERE file_id=? AND owner=?''', (file_id, username))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return jsonify({'error': 'File not found or unauthorized access'}), 404
    
    encrypted_key = result[0].encode()
    encrypted_content = result[1]
    
    # Return the encrypted content and the key for decryption
    return jsonify({
        'message': 'File downloaded successfully',
        'encrypted_content': encrypted_content.decode(),
        'decryption_key': encrypted_key.decode()
    }), 200

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Secure Online Storage Server')
    parser.add_argument('--host', type=str, default='127.0.0.1',
                        help='Hostname or IP address to run the server on')
    parser.add_argument('--port', type=int, default=5000,
                        help='Port number to run the server on')
    args = parser.parse_args()
    
    print("Server listening on 127.0.0.1:5000 ")
    app.run(host=args.host, port=args.port)