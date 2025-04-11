from client_utils import (
    register_user,
    login_user,
    upload_file,
    download_file
)
import getpass
import os
import tkinter as tk
from tkinter import filedialog
from cryptography.fernet import Fernet

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

        # Initialize Tkinter
        TK = tk.Tk()
        TK.withdraw()  # Hide the main window
    
        # Open file dialog
        filename = filedialog.askopenfilename(title="Select a file to upload")
        if not filename:  # If no file is selected, filename will be an empty string
            print("No file selected.")
            return

        if not os.path.exists(filename):
            print("File not found.")
            return

        # Read the file content
        with open(filename, 'rb') as f:
            file_content = f.read()

        # Generate a key for encryption
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        encrypted_content = cipher_suite.encrypt(file_content)

        # Get the filename
        file_name = os.path.basename(filename)

        # Upload the file
        result = upload_file(
            self.server_url,
            self.username,
            file_name,
            encrypted_content.decode(),
            key.decode()
        )

        if 'message' in result:
            print(result['message'])
        else:
            print(f"Error: {result.get('error', 'Upload failed')}")

    def download_file(self):
        if not self.username:
            print("Please login first.")
            return
        
        file_id = input("Enter file ID: ")
        result = download_file(self.server_url, self.username, file_id)
        
        if 'message' in result:
            # Extract the necessary information
            encrypted_content = result.get('encrypted_content', None)
            decryption_key = result.get('decryption_key', None)
            
            if not encrypted_content or not decryption_key:
                print("Error: Missing file content or decryption key.")
                return

            # Save the file
            filename = os.path.basename(result.get('filename', 'downloaded_file'))
            with open(filename, 'wb') as f:
                f.write(encrypted_content.encode())

            # Decrypt the file
            key = decryption_key.encode()
            cipher_suite = Fernet(key)
            with open(filename, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = cipher_suite.decrypt(encrypted_data)

            # Save the decrypted content
            with open(filename, 'wb') as f:
                f.write(decrypted_data)

            print(f"File saved as: {filename}")
        else:
            print(f"Error: {result.get('error', 'Download failed')}")

def main():
    # Get server hostname and port from user
    server_host = input("Enter server hostname (default: 127.0.0.1): ") or '127.0.0.1'
    server_port = input("Enter server port (default: 5000): ") or '5000'
    
    # Use HTTP for testing without SSL issues
    server_url = f"http://{server_host}:{server_port}"
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