import requests
import getpass
import hashlib
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class Client:
    def __init__(self, server_url):
        self.server_url = server_url
        self.username = None
        self.session_key = None

    def register(self):
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        
        data = {
            'username': username,
            'password': password
        }
        
        response = requests.post(f"{self.server_url}/register", json=data)
        if response.status_code == 200:
            print("Registration successful!")
        else:
            print(f"Error: {response.json().get('error')}")

    def login(self):
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        
        data = {
            'username': username,
            'password': password
        }
        
        response = requests.post(f"{self.server_url}/login", json=data)
        if response.status_code == 200:
            self.username = username
            print("Login successful!")
        else:
            print(f"Error: {response.json().get('error')}")

    def upload_file(self):
        if not self.username:
            print("Please login first.")
            return
        
        filename = input("Enter filename: ")
        # Read file content
        with open(filename, 'rb') as f:
            file_content = f.read()
        
        # Generate a random key for encryption
        key = Fernet.generate_key()
        f = Fernet(key)
        encrypted_content = f.encrypt(file_content)
        
        data = {
            'username': self.username,
            'filename': filename,
            'encrypted_file': encrypted_content.decode()
        }
        
        response = requests.post(f"{self.server_url}/upload", json=data)
        if response.status_code == 200:
            print("File uploaded successfully!")
        else:
            print(f"Error: {response.json().get('error')}")

    def download_file(self):
        if not self.username:
            print("Please login first.")
            return
        
        file_id = input("Enter file ID: ")
        
        data = {
            'username': self.username,
            'file_id': file_id
        }
        
        response = requests.post(f"{self.server_url}/download", json=data)
        if response.status_code == 200:
            print("File downloaded successfully!")
            # Save the decrypted content to a file
            with open('downloaded_' + os.path.basename(response.json().get('filename')), 'wb') as f:
                f.write(response.json().get('file_content'))
        else:
            print(f"Error: {response.json().get('error')}")

def main():
    server_url = 'https://localhost:5000'
    client = Client(server_url)
    
    while True:
        print("\nMenu:")
        print("1. Register")
        print("2. Login")
        print("3. Upload file")
        print("4. Download file")
        print("5. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            client.register()
        elif choice == '2':
            client.login()
        elif choice == '3':
            client.upload_file()
        elif choice == '4':
            client.download_file()
        elif choice == '5':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()