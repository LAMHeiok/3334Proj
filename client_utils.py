import requests
import hashlib
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import logging

# Configure logging
logging.basicConfig(filename='client.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_password_hash(password, salt):
    """Generate a password hash using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(content):
    """Encrypt the given content using Fernet."""
    key = Fernet.generate_key()
    f = Fernet(key)
    encrypted_content = f.encrypt(content)
    return key, encrypted_content

def decrypt_file(encrypted_content, key):
    """Decrypt the given content using the provided key."""
    f = Fernet(key)
    return f.decrypt(encrypted_content)

def make_request(server_url, endpoint, data=None, method='POST'):
    """Make an HTTP request to the server."""
    try:
        response = requests.request(method, f"{server_url}/{endpoint}", json=data)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {str(e)}")
        return {'error': str(e)}

def register_user(server_url, username, password):
    """Register a new user."""
    data = {
        'username': username,
        'password': password
    }
    result = make_request(server_url, 'register', data)
    if 'error' in result:
        logging.error(f"Registration error: {result['error']}")
    return result

def login_user(server_url, username, password):
    """Login an existing user."""
    data = {
        'username': username,
        'password': password
    }
    result = make_request(server_url, 'login', data)
    if 'error' in result:
        logging.error(f"Login error: {result['error']}")
    return result

def upload_file(server_url, username, filename):
    """Upload a file to the server."""
    try:
        with open(filename, 'rb') as f:
            content = f.read()
        
        key, encrypted_content = encrypt_file(content)
        
        data = {
            'username': username,
            'filename': filename,
            'encrypted_file': encrypted_content.decode(),
            'key': key.decode()
        }
        
        result = make_request(server_url, 'upload', data)
        if 'error' in result:
            logging.error(f"Upload error: {result['error']}")
        return result
    except Exception as e:
        logging.error(f"Upload error: {str(e)}")
        return {'error': str(e)}

def download_file(server_url, username, file_id):
    """Download a file from the server."""
    data = {
        'username': username,
        'file_id': file_id
    }
    result = make_request(server_url, 'download', data)
    if 'error' in result:
        logging.error(f"Download error: {result['error']}")
        return result
    
    encrypted_content = result.get('encrypted_file', None)
    key = result.get('key', None)
    
    if encrypted_content and key:
        decrypted_content = decrypt_file(encrypted_content.encode(), key.encode())
        return {'content': decrypted_content, 'message': result.get('message', '')}
    return result