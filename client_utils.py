import requests
import pyotp
import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def generate_key_pair(username):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    with open(f"{username}_private.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(f"{username}_public.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return private_key, public_key

def register_user(server_url, username, password):
    private_key, public_key = generate_key_pair(username)
    salt = os.urandom(16)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    # Generate TOTP secret
    totp_secret = pyotp.random_base32()
    with open(f"{username}_totp_secret.txt", "w") as f:
        f.write(totp_secret)

    response = requests.post(
        f"{server_url}/register",
        json={
            "username": username,
            "password": password,
            "salt": salt.hex(),
            "public_key": public_key_pem,
            "totp_secret": totp_secret,
        },
    )
    print(f"Raw server response: {response.text}")  # Debug
    print(f"Response status code: {response.status_code}")  # Debug
    try:
        result = response.json()
    except requests.exceptions.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        print(f"Response content: {response.text}")
        return {"error": "invalid_response", "error_description": "Server returned invalid JSON"}

    print(f"TOTP Secret (save this or scan QR): {totp_secret}")
    print(f"Use an authenticator app (e.g., Google Authenticator) to generate OTPs.")
    return result

def login_user(server_url, username, password, totp_code=None):
    response = requests.post(
        f"{server_url}/login",
        json={"username": username, "password": password, "totp_code": totp_code},
    )
    return response.json()

def initiate_fido2_registration(server_url, username):
    response = requests.post(
        f"{server_url}/fido2/register_begin",
        json={"username": username},
    )
    print(f"Initiate registration response: {response.text}")  # Debug
    return response.json()

def complete_fido2_registration(server_url, username, credential_data):
    response = requests.post(
        f"{server_url}/fido2/register_complete",
        json={"username": username, "credential_data": credential_data},
    )
    print(f"Complete registration response: {response.text}")  # Debug
    return response.json()

def initiate_fido2_authentication(server_url, username):
    response = requests.post(
        f"{server_url}/fido2/authenticate_begin",
        json={"username": username},
    )
    print(f"Initiate authentication response: {response.text}")  # Debug
    return response.json()

def complete_fido2_authentication(server_url, username, assertion_data):
    response = requests.post(
        f"{server_url}/fido2/authenticate_complete",
        json={"username": username, "assertion_data": assertion_data},
    )
    print(f"Complete authentication response: {response.text}")  # Debug
    return response.json()

def upload_file(server_url, username, filename):
    with open(f"{username}_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    fernet_key = Fernet.generate_key()
    fernet = Fernet(fernet_key)
    with open(filename, "rb") as f:
        file_content = f.read()
    encrypted_content = fernet.encrypt(file_content)
    encrypted_key = public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    response = requests.post(
        f"{server_url}/upload",
        json={
            "username": username,
            "filename": os.path.basename(filename),
            "encrypted_file": base64.b64encode(encrypted_content).decode(),
            "encrypted_key": base64.b64encode(encrypted_key).decode(),
        },
    )
    return response.json()

def download_file(server_url, username, file_id):
    response = requests.post(
        f"{server_url}/download",
        json={"username": username, "file_id": file_id},
    )
    return response.json()

def share_file(server_url, username, file_id, shared_with):
    response = requests.post(
        f"{server_url}/get_public_key",
        json={"username": shared_with},
    )
    result = response.json()
    if "public_key" not in result:
        return result
    public_key = serialization.load_pem_public_key(result["public_key"].encode())
    with open(f"{username}_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    download_result = download_file(server_url, username, file_id)
    if "encrypted_key" not in download_result:
        return download_result
    encrypted_key = base64.b64decode(download_result["encrypted_key"])
    fernet_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    encrypted_key_for_shared = public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    response = requests.post(
        f"{server_url}/share",
        json={
            "username": username,
            "file_id": file_id,
            "shared_with": shared_with,
            "encrypted_key": base64.b64encode(encrypted_key_for_shared).decode(),
        },
    )
    return response.json()

def list_files(server_url, username):
    response = requests.post(
        f"{server_url}/list_files",
        json={"username": username},
    )
    return response.json()

def delete_file(server_url, username, file_id):
    response = requests.post(
        f"{server_url}/delete_file",
        json={"username": username, "file_id": file_id},
    )
    return response.json()

def revoke_share(server_url, username, file_id, shared_with):
    response = requests.post(
        f"{server_url}/revoke_share",
        json={
            "username": username,
            "file_id": file_id,
            "shared_with": shared_with,
        },
    )
    return response.json()

def reset_password(server_url, username, old_password, new_password):
    response = requests.post(
        f"{server_url}/reset_password",
        json={
            "username": username,
            "old_password": old_password,
            "new_password": new_password,
        },
    )
    return response.json()