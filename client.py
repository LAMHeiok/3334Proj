from client_utils import (
    register_user,
    login_user,
    upload_file,
    download_file,
    share_file
)
import getpass
import os
import tkinter as tk
from tkinter import filedialog
import base64  # 新增導入

class Client:
    def __init__(self, server_url):
        self.server_url = server_url
        self.username = None

    def register(self):
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        result = register_user(self.server_url, username, password)
        if 'message' in result:
            print(result['message'])
        else:
            print(f"Error: {result.get('error', 'Registration failed')}")

    def login(self):
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        result = login_user(self.server_url, username, password)
        if 'message' in result:
            self.username = username
            print(result['message'])
        else:
            print(f"Error: {result.get('error', 'Login failed')}")

    def upload_file(self):
        if not self.username:
            print("Please login first.")
            return

        TK = tk.Tk()
        TK.withdraw()
        filename = filedialog.askopenfilename(title="Select a file to upload")
        if not filename:
            print("No file selected.")
            return

        if not os.path.exists(filename):
            print("File not found.")
            return

        result = upload_file(self.server_url, self.username, filename)
        if 'message' in result:
            file_id = result.get('file_id')
            print(f"{result['message']} (File ID: {file_id})")
        else:
            print(f"Error: {result.get('error', 'Upload failed')}")

    def download_file(self):
        if not self.username:
            print("Please login first.")
            return
        
        file_id = input("Enter file ID: ")
        result = download_file(self.server_url, self.username, file_id)
        
        if 'encrypted_content' in result and 'filename' in result and 'encrypted_key' in result:
            private_key_file = f"{self.username}_private.pem"
            if not os.path.exists(private_key_file):
                print(f"Error: Private key not found (expected: {private_key_file}).")
                return
            
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.fernet import Fernet
            
            # Load private key
            with open(private_key_file, 'rb') as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            
            # Decrypt the Fernet key
            try:
                encrypted_key = base64.b64decode(result['encrypted_key'])
                fernet_key = private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Decrypt the file content
                fernet = Fernet(fernet_key)
                decrypted_content = fernet.decrypt(result['encrypted_content'].encode())
                filename = input(f"Enter filename to save as (default: {result['filename']}): ") or result['filename']
                with open(filename, 'wb') as f:
                    f.write(decrypted_content)
                print(f"File saved as: {filename}")
            except Exception as e:
                print(f"Error: Failed to decrypt file - {str(e)}")
        else:
            print(f"Error: {result.get('error', 'Download failed')}")

    def share_file(self):
        if not self.username:
            print("Please login first.")
            return
        
        file_id = input("Enter file ID to share: ")
        shared_with = input("Enter username to share with: ")
        result = share_file(self.server_url, self.username, file_id, shared_with)
        
        if 'message' in result:
            print(result['message'])
        else:
            print(f"Error: {result.get('error', 'Sharing failed')}")

def main():
    server_host = input("Enter server hostname (default: 127.0.0.1): ") or '127.0.0.1'
    server_port = input("Enter server port (default: 5000): ") or '5000'
    server_url = f"http://{server_host}:{server_port}"
    client = Client(server_url)
    
    while True:
        print("\nMenu:")
        print("1. Register")
        print("2. Login")
        print("3. Upload file")
        print("4. Download file")
        print("5. Share file")
        print("6. Exit")
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
            client.share_file()
        elif choice == '6':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()