from client_utils import (
    register_user,
    login_user,
    upload_file,
    download_file,
    share_file,
    list_files,
    delete_file,
    revoke_share,
    reset_password,
)
import getpass
import os
import tkinter as tk
from tkinter import filedialog
import base64
import pyotp
import json

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
            print(f"Save your TOTP secret (displayed during registration) in an authenticator app.")
        else:
            print(f"Error: {result.get('error_description', 'Registration failed')}")

    def login(self):
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        totp_code = input("Enter TOTP code (leave blank if not set up): ") or None
        result = login_user(self.server_url, username, password, totp_code)
        if 'message' in result:
            self.username = username
            print(result['message'])
        else:
            print(f"Error: {result.get('error_description', 'Login failed')}")

    def upload_file(self):
        if not self.username:
            print("Error: Please log in first")
            return
        TK = tk.Tk()
        filename = filedialog.askopenfilename(title="Select a file to upload")
        if not filename:
            print("Error: No file selected")
            return
        if not os.path.exists(filename):
            print("Error: File does not exist")
            return
        TK.destroy()
        result = upload_file(self.server_url, self.username, filename)
        if 'message' in result:
            file_id = result.get('file_id')
            print(f"{result['message']} (File ID: {file_id})")
        else:
            print(f"Error: {result.get('error_description', 'Upload failed')}")

    def download_file(self):
        if not self.username:
            print("Error: Please log in first")
            return
        file_id = input("Enter file ID: ")
        # Call the download_file function from client_utils.py
        result = download_file(self.server_url, self.username, file_id)
        if 'message' in result:
            print(result['message'])
        else:
            print(f"Error: {result.get('error_description', 'Download failed')}")

    def share_file(self):
        if not self.username:
            print("Error: Please log in first")
            return
        file_id = input("Enter file ID to share: ")
        shared_with = input("Enter username to share with: ")
        result = share_file(self.server_url, self.username, file_id, shared_with)
        if 'message' in result:
            print(result['message'])
        else:
            print(f"Error: {result.get('error_description', 'Sharing failed')}")

    def list_files(self):
        if not self.username:
            print("Error: Please log in first")
            return
        result = list_files(self.server_url, self.username)
        if 'owned_files' in result:
            print("Owned files:")
            if not result['owned_files']:
                print("  (None)")
            for f in result['owned_files']:
                print(f"  ID: {f['file_id']}, Name: {f['filename']}")
            print("Shared with me:")
            if not result['shared_files']:
                print("  (None)")
            for f in result['shared_files']:
                print(f"  ID: {f['file_id']}, Name: {f['filename']}")
        else:
            print(f"Error: {result.get('error_description', 'Failed to list files')}")

    def delete_file(self):
        if not self.username:
            print("Error: Please log in first")
            return
        file_id = input("Enter file ID to delete: ")
        result = delete_file(self.server_url, self.username, file_id)
        if 'message' in result:
            print(result['message'])
        else:
            print(f"Error: {result.get('error_description', 'Deletion failed')}")

    def revoke_share(self):
        if not self.username:
            print("Error: Please log in first")
            return
        file_id = input("Enter file ID to revoke sharing: ")
        shared_with = input("Enter username to revoke sharing from: ")
        result = revoke_share(self.server_url, self.username, file_id, shared_with)
        if 'message' in result:
            print(result['message'])
        else:
            print(f"Error: {result.get('error_description', 'Revoke sharing failed')}")

    def reset_password(self):
        if not self.username:
            print("Error: Please log in first")
            return
        old_password = getpass.getpass("Enter current password: ")
        new_password = getpass.getpass("Enter new password: ")
        confirm_password = getpass.getpass("Confirm new password: ")
        if new_password != confirm_password:
            print("Error: New password and confirmation do not match")
            return
        result = reset_password(self.server_url, self.username, old_password, new_password)
        if 'message' in result:
            print(result['message'])
        else:
            print(f"Error: {result.get('error_description', 'Password reset failed')}")


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
        print("6. List files")
        print("7. Delete file")
        print("8. Revoke share")
        print("9. Reset password")
        print("10. Exit")
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
            client.list_files()
        elif choice == '7':
            client.delete_file()
        elif choice == '8':
            client.revoke_share()
        elif choice == '9':
            client.reset_password()
        elif choice == '10':
            break
        else:
            print("Error: Invalid choice. Please try again.")


if __name__ == '__main__':
    main()