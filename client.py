from client_utils import (
    register_user,
    login_user,
    upload_file,
    download_file
)
import getpass
import os

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
        
        filename = input("Enter filename: ")
        if not os.path.exists(filename):
            print("File not found.")
            return
        
        result = upload_file(self.server_url, self.username, filename)
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
        
        if 'content' in result:
            filename = os.path.basename(result.get('filename', 'downloaded_file'))
            with open(filename, 'wb') as f:
                f.write(result['content'])
            print(f"File saved as: {filename}")
        else:
            print(f"Error: {result.get('error', 'Download failed')}")

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