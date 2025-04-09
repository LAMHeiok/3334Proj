import sqlite3

def init_db():
    conn = sqlite3.connect('storage.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, 
                  public_key BLOB, encrypted_private_key BLOB, salt BLOB, 
                  encrypted_master_key BLOB)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY, owner_id INTEGER, encrypted_content BLOB, 
                  nonce BLOB, file_name TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS file_keys
                 (file_id INTEGER, user_id INTEGER, encrypted_key BLOB,
                  FOREIGN KEY(file_id) REFERENCES files(id),
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT, 
                  timestamp DATETIME, details TEXT)''')
    
    conn.commit()
    conn.close()

init_db()