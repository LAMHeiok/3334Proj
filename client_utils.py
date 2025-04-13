import requests
import pyotp
import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken


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

def download_file(server_url, username, file_id, save_file=True):
    try:
        response = requests.post(
            f"{server_url}/download",
            json={"username": username, "file_id": file_id},
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return {"error": "request_failed", "error_description": str(e)}

    try:
        result = response.json()
    except requests.exceptions.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        print(f"Response content: {response.text}")
        return {"error": "invalid_response", "error_description": "Server returned invalid JSON"}

    if "error" in result:
        return result

    try:
        encrypted_key = base64.b64decode(result["encrypted_key"])
    except TypeError as e:
        print(f"Failed to decode encrypted_key: {e}")
        return {"error": "decoding_error", "error_description": "Failed to decode encrypted key"}

    private_key_path = f"{username}_private.pem"
    try:
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except Exception as e:
        print(f"Failed to load private key: {e}")
        return {"error": "key_error", "error_description": "Failed to load private key"}

    try:
        fernet_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        print(f"Decryption failed: {e}")
        return {"error": "decryption_failed", "error_description": "Failed to decrypt Fernet key"}

    try:
        fernet = Fernet(fernet_key)
        encrypted_content = base64.b64decode(result["encrypted_content"])
        decrypted_content = fernet.decrypt(encrypted_content)
    except Exception as e:
        print(f"File decryption failed: {e}")
        return {"error": "file_decryption_failed", "error_description": "Failed to decrypt file content"}

    if save_file:
        output_filename = result['filename']
        try:
            with open(output_filename, "wb") as f:
                f.write(decrypted_content)
            return {
                'message': f'File downloaded and saved successfully as {output_filename}',
                'filename': output_filename
            }
        except Exception as e:
            print(f"Failed to save file: {e}")
            return {"error": "file_save_failed", "error_description": f"Failed to save file: {str(e)}"}
    else:
        # Return data without saving for use in sharing
        return {
            'message': 'File data retrieved successfully',
            'filename': result['filename'],
            'encrypted_key': result['encrypted_key'],  # Base64-encoded string
            'decrypted_content': decrypted_content  # For potential future use
        }

def share_file(server_url, username, file_id, shared_with):
    # Get the target user's public key
    response = requests.post(
        f"{server_url}/get_public_key",
        json={"username": shared_with},
    )
    result = response.json()
    if "public_key" not in result:
        return result
    try:
        public_key = serialization.load_pem_public_key(result["public_key"].encode())
    except Exception as e:
        return {"error": "public_key_error", "error_description": f"Failed to load public key: {str(e)}"}

    # Download the file's encrypted key (without saving the file)
    download_result = download_file(server_url, username, file_id, save_file=False)
    if "error" in download_result:
        return download_result

    # Load the owner's private key
    try:
        with open(f"{username}_private.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except Exception as e:
        return {"error": "private_key_error", "error_description": f"Failed to load private key: {str(e)}"}

    # Decrypt the Fernet key
    try:
        encrypted_key = base64.b64decode(download_result["encrypted_key"])
        fernet_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        return {"error": "decryption_failed", "error_description": f"Failed to decrypt Fernet key: {str(e)}"}

    # Re-encrypt the Fernet key for the shared_with user
    try:
        encrypted_key_for_shared = public_key.encrypt(
            fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        return {"error": "encryption_failed", "error_description": f"Failed to encrypt key for sharing: {str(e)}"}

    # Send the share request
    response = requests.post(
        f"{server_url}/share",
        json={
            "username": username,
            "file_id": file_id,
            "shared_with": shared_with,
            "encrypted_key": base64.b64encode(encrypted_key_for_shared).decode(),
        },
    )
    try:
        return response.json()
    except requests.exceptions.JSONDecodeError as e:
        return {"error": "server_response_error", "error_description": f"Invalid server response: {str(e)}"}

def decrypt_file(username, download_result, output_filename):
    try:
        # Load the private key
        with open(f"{username}_private.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Extract and decode data from server response
        encrypted_key = base64.b64decode(download_result["encrypted_key"])
        encrypted_content = base64.b64decode(download_result["encrypted_content"])

        # Decrypt the Fernet key
        fernet_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Decrypt the file content
        fernet = Fernet(fernet_key)
        decrypted_content = fernet.decrypt(encrypted_content)

        # Save the decrypted file
        with open(output_filename, "wb") as f:
            f.write(decrypted_content)

        return {"message": f"File decrypted and saved as {output_filename}"}

    except FileNotFoundError:
        return {"error": "private_key_not_found", "error_description": f"Private key file {username}_private.pem not found"}
    except ValueError as e:
        return {"error": "decryption_failed", "error_description": f"RSA decryption failed: {str(e)}"}
    except InvalidToken:
        return {"error": "decryption_failed", "error_description": "Fernet decryption failed: Invalid key or corrupted content"}
    except Exception as e:
        return {"error": "decryption_failed", "error_description": f"Unexpected error: {str(e)}"}

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