import os
import base64
import getpass
import json
import hashlib
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class PasswordManager:
    def __init__(self, file_path="passwords.enc"):
        self.file_path = file_path
        self.passwords = {}
        self.salt = None
        self.master_key = None
    
    def generate_master_key(self, master_password):
        """Generate a secure key from the master password using PBKDF2"""
        if not self.salt:
            self.salt = os.urandom(16)

        # Use PBKDF2 with high iteration count (100,000+) for key stretching
        kdf = PBKDF2HMAC (
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )

        # Derive the key from the password
        self.master_key = kdf.derive(master_password.encode())

    def encrypt_data(self, data):
        """Encrypt data with AES-GCM"""
        if not self.master_key:
            raise ValueError("Master Key not initialized")
        
        # Convert data to JSON string
        data_json = json.dumps(data)

        # Generate a random nonce for AES-GCM
        nonce = os.urandom(12)
          
        # Encrypt the data
        aesgcm = AESGCM(self.master_key)
        ciphertext = aesgcm.encrypt(nonce, data_json.encode(), None)
        
        # Combine nonce and ciphertext for storage
        encrypted_data = {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "salt": base64.b64encode(self.salt).decode()
        }
        
        return encrypted_data
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data with AES-GCM"""
        if not self.master_key:
            raise ValueError("Master key not initialized")
        
        # Get the nonce and ciphertext
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        
        # Decrypt the data
        aesgcm = AESGCM(self.master_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Parse the JSON data
        return json.loads(plaintext.decode())
    
    def save(self):
        """Save encrypted password data to file"""
        if not self.passwords:
            return
            
        encrypted_data = self.encrypt_data(self.passwords)
        
        with open(self.file_path, "w") as f:
            json.dump(encrypted_data, f)
    
    def load(self, master_password):
        """Load and decrypt password data from file"""
        try:
            with open(self.file_path, "r") as f:
                encrypted_data = json.load(f)
            
            # Load the salt
            self.salt = base64.b64decode(encrypted_data["salt"])
            
            # Generate the master key
            self.generate_master_key(master_password)
            
            # Decrypt the data
            self.passwords = self.decrypt_data(encrypted_data)
            
            return True
        except (FileNotFoundError, json.JSONDecodeError, ValueError):
            return False
    
    def add_password(self, service, username, password):
        """Add or update a password entry"""
        self.passwords[service] = {
            "username": username,
            "password": password
        }
    
    def get_password(self, service):
        """Retrieve a password entry"""
        return self.passwords.get(service)
    
    def generate_password(self, length=16):
        """Generate a strong random password"""
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
        return ''.join(secrets.choice(charset) for _ in range(length))

# Example usage
def main():
    pm = PasswordManager()
    
    print("===== Secure Password Manager =====")
    
    # Try to load existing passwords
    master_password = getpass.getpass("Enter master password: ")
    if not pm.load(master_password):
        print("Creating new password database...")
        pm.generate_master_key(master_password)
    
    while True:
        print("\n1. Add/Update Password")
        print("2. Get Password")
        print("3. Generate Strong Password")
        print("4. Save and Exit")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == "1":
            service = input("Service name: ")
            username = input("Username: ")
            password = getpass.getpass("Password (leave empty to generate): ")
            
            if not password:
                password = pm.generate_password()
                print(f"Generated password: {password}")
            
            pm.add_password(service, username, password)
            print(f"Password for {service} saved.")
            
        elif choice == "2":
            service = input("Service name: ")
            entry = pm.get_password(service)
            
            if entry:
                print(f"Username: {entry['username']}")
                print(f"Password: {entry['password']}")
            else:
                print(f"No entry found for {service}")
                
        elif choice == "3":
            length = int(input("Password length (default: 16): ") or 16)
            password = pm.generate_password(length)
            print(f"Generated password: {password}")
            
        elif choice == "4":
            pm.save()
            print("Passwords saved. Goodbye!")
            break
            
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()