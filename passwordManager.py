import os
from Crypto.Random import get_random_bytes

class PasswordManager:
    def __init__(self, vault_name):
        self.vault_name = vault_name
        self.vault_file = f"{vault_name}.vault"
        self.key_file = f"key-{vault_name}.txt"
        self.key = self.load_key()
        self.load_vault()
    
    # Load or generate AES encryption key
    def load_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as file:
                return file.read()
        
        else:
            key = get_random_bytes(32)
            with open(self.key_file, "wb") as file:
                return file.write(key)
    