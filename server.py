from flask import Flask, request, jsonify
import sqlite3
import hashlib
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import logging
import argparse
import pyotp
import json

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
                  public_key TEXT,
                  totp_secret TEXT,
                  fido2_credentials TEXT)''')
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
    totp_secret = data.get('totp_secret')
    if not all([username, password, salt, public_key, totp_secret]):
        return jsonify({
            'error': 'missing_fields',
            'error_description': 'Please enter all required fields'
        }), 400

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', (username,))
    if c.fetchone():
        conn.close()
        return jsonify({
            'error': 'username_exists',
            'error_description': 'This username is already taken'
        }), 400

    password_hash = hash_password(password, salt).decode()
    c.execute(
        'INSERT INTO users (username, password_hash, salt, public_key, totp_secret, fido2_credentials) VALUES (?, ?, ?, ?, ?, ?)',
        (username, password_hash, salt.hex(), public_key, totp_secret, json.dumps([])))
    conn.commit()
    conn.close()
    logging.info(f"New user registered: {username}")
    return jsonify({'message': 'User registered successfully'}), 200


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    totp_code = data.get('totp_code')
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

    if not user:
        return jsonify({
            'error': 'invalid_credentials',
            'error_description': 'Incorrect username or password'
        }), 401

    # Verify password
    if hash_password(password, bytes.fromhex(user[2])) != user[1].encode():
        return jsonify({
            'error': 'invalid_credentials',
            'error_description': 'Incorrect username or password'
        }), 401

    # Verify TOTP if provided
    if user[4]:  # totp_secret exists
        if not totp_code:
            return jsonify({
                'error': 'totp_required',
                'error_description': 'TOTP code required'
            }), 401
        totp = pyotp.TOTP(user[4])
        if not totp.verify(totp_code):
            return jsonify({
                'error': 'invalid_totp',
                'error_description': 'Invalid TOTP code'
            }), 401

    logging.info(f"User logged in: {username}")
    return jsonify({'message': 'Login successful'}), 200

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Secure Online Storage Server')
    parser.add_argument('--host', type=str, default='127.0.0.1',
                        help='Hostname or IP address to run the server on')
    parser.add_argument('--port', type=int, default=5000,
                        help='Port number to run the server on')
    args = parser.parse_args()
    print("Server listening on 127.0.0.1:5000")
    app.run(host=args.host, port=args.port)