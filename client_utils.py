import requests
import hashlib
import os
import re
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import logging

logging.basicConfig(filename='client.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_password_hash(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def generate_key_pair(username):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    with open(f"{username}_private.pem", 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def encrypt_file(content):
    key = Fernet.generate_key()
    f = Fernet(key)
    encrypted_content = f.encrypt(content)
    return key, encrypted_content

def make_request(server_url, endpoint, data=None, method='POST'):
    try:
        response = requests.post(f"{server_url}/{endpoint}", json=data) if method == 'POST' else None
        response.raise_for_status()
        result = response.json()
        logging.info(f"Request to {endpoint} with data {data} returned: {result}")
        return result
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error to {endpoint}: {str(e)}")
        return {'error': str(e)}

def register_user(server_url, username, password):
    # Username validation
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        print("Error: Invalid username. Please use only alphanumeric characters and underscores.")  # Print error to console
        logging.error("Invalid username provided. Registration aborted.") # Log the error
        return {'error': 'invalid_username', 'error_description': 'Invalid username format'}  # Return an error dictionary

    salt = os.urandom(16)
    password_hash = generate_password_hash(password, salt)
    public_key = generate_key_pair(username) #key pair will only be generated if username is valid
    data = {
        'username': username,
        'password': password_hash.decode(),
        'salt': salt.hex(),
        'public_key': public_key.decode()
    }
    result = make_request(server_url, 'register', data)
    if 'error' in result:
        logging.error(f"Registration error: {result['error']}")
    return result

def login_user(server_url, username, password):
    data = {'username': username, 'password': password}
    result = make_request(server_url, 'login', data)
    if 'error' in result:
        logging.error(f"Login error: {result['error']}")
    return result

def upload_file(server_url, username, filename):
    try:
        with open(filename, 'rb') as f:
            content = f.read()
        key, encrypted_content = encrypt_file(content)
        
        data = {
            'username': username,
            'filename': os.path.basename(filename),
            'encrypted_file': encrypted_content.decode(),
            'encrypted_key': base64.b64encode(key).decode()
        }
        result = make_request(server_url, 'upload', data)
        if 'error' in result:
            logging.error(f"Upload error: {result['error']}")
        return result
    except Exception as e:
        logging.error(f"Upload error: {str(e)}")
        return {'error': str(e)}

def download_file(server_url, username, file_id):
    data = {'username': username, 'file_id': file_id}
    result = make_request(server_url, 'download', data)
    if 'error' in result:
        logging.error(f"Download error: {result['error']}")
    return result

def share_file(server_url, username, file_id, shared_with):
    response = make_request(server_url, 'get_public_key', {'username': shared_with})
    if 'public_key' not in response:
        error_msg = response.get('error', 'Failed to fetch public key')
        if 'User not found' in error_msg:
            return {'error': f"User '{shared_with}' does not exist. Please ask them to register first."}
        return {'error': error_msg}
    
    public_key = serialization.load_pem_public_key(response['public_key'].encode())
    
    private_key_file = f"{username}_private.pem"
    if not os.path.exists(private_key_file):
        return {'error': f"Private key not found (expected: {private_key_file})"}
    
    with open(private_key_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    
    file_data = make_request(server_url, 'download', {'username': username, 'file_id': file_id})
    if 'encrypted_key' not in file_data:
        return {'error': f"Failed to fetch file data for sharing: {file_data.get('error', 'Unknown error')}"}
    
    encrypted_key = base64.b64decode(file_data['encrypted_key'])
    try:
        fernet_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    except Exception as e:
        return {'error': f"Failed to decrypt Fernet key: {str(e)}"}
    
    encrypted_key_for_shared = public_key.encrypt(
        fernet_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    data = {
        'username': username,
        'file_id': file_id,
        'shared_with': shared_with,
        'encrypted_key': base64.b64encode(encrypted_key_for_shared).decode()
    }
    result = make_request(server_url, 'share', data)
    if 'error' in result:
        logging.error(f"Share error: {result['error']}")
    return result

def list_files(server_url, username):
    data = {'username': username}
    result = make_request(server_url, 'list_files', data)
    if 'error' in result:
        logging.error(f"List files error: {result['error']}")
    return result

def delete_file(server_url, username, file_id):
    data = {'username': username, 'file_id': file_id}
    result = make_request(server_url, 'delete_file', data)
    if 'error' in result:
        logging.error(f"Delete file error: {result['error']}")
    return result

def revoke_share(server_url, username, file_id, shared_with):
    data = {'username': username, 'file_id': file_id, 'shared_with': shared_with}
    result = make_request(server_url, 'revoke_share', data)
    if 'error' in result:
        logging.error(f"Revoke share error: {result['error']}")
    return result

def reset_password(server_url, username, old_password, new_password):
    data = {'username': username, 'old_password': old_password, 'new_password': new_password}
    result = make_request(server_url, 'reset_password', data)
    if 'error' in result:
        logging.error(f"Reset password error: {result['error']}")
    return result