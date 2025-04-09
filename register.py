# Client Side
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
import bcrypt, os

def register(username, password):
    # Hash password
    salt = bcrypt.gensalt()
    hashed_pw = bcrypt.hashpw(password.encode(), salt)
    
    # Generate RSA keys
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Encrypt private key using password-derived key
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=os.urandom(16), iterations=100000)
    key = kdf.derive(password.encode())
    # ... encrypt private_key with key and store as encrypted_private_key
    
    # Send to server
    send_to_server({
        'action': 'register',
        'username': username,
        'hashed_pw': hashed_pw,
        'public_key': public_key,
        'encrypted_private_key': encrypted_private_key,
        'salt': salt
    })