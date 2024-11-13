import os
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json

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
    
    # Load encrypted* vault data
    def load_vault(self):
        if os.path.exists(self.key_file):
            with open(self.vault_file, "rb") as file:
                encrypted_content = file.read()
            # Create cipher + iv
            cipher = AES.new(self.key, AES.MODE_CBC, iv=encrypted_content[:16])
            # REMOVE PADDING
            decrypted_content = unpad(cipher.decrypt(encrypted_content[16:]), AES.block_size)
            # Set vault as decrypted data
            self.vault = json.loads(decrypted_content.decode())
        else:
            self.vault = {}
    
    # Encrypt & save data into vault
    def save_vault(self):
        data = json.dumps(self.vault)
        cipher = AES.new(self.key, AES.MODE_CBC)
        # Encrypt data & add padding
        encrypt_data = cipher.encrypt(pad(data.encode(), AES.block_size))
        with open(self.vault_file, "wb") as file:
            file.write(cipher.iv + encrypt_data)
    
    # List password & list them as most recent = smallest num & least recent = biggest num
    def list_passwords(self):
        if not self.vault():
            print("No password created.")
            return
        sorted_passwords = sorted(self.vault.keys(), key=lambda x: -len(x))
        print("Stored Passwords:")
        for i, name in enumerate(sorted_passwords, 1):
            print(f"{i}. {name}")

    # Get password (show password)
    def get_password(self):
        self.list_passwords()
        try:
            index = int(input('Enter the number of the password to view: '))
            sorted_passwords = sorted(self.vault.keys(), key=lambda x: -len(x))
            selected_name = sorted_passwords[index - 1]
            print(f"Password for '{selected_name}': {self.vault[selected_name]}")
        except (ValueError, IndexError):
            print("Invalid selection, try again.")

    # Create password for entry (entry = the data saved)
    def create_password(self):
        name = input("Enter password name: ")
        # Verify if exist
        while name in self.vault:
            print("Name is already in use, enter another one: ")
            name = input("Enter password name: ")
        
        password = input("Enter password: ")
        confirm_password = input("Retype password: ")
        # Don't match
        while password != confirm_password:
            print("Password does not match, try again.")
            password = input("Enter password: ")
            confirm_password = input("Retype password: ")
        
        # Save in vault
        self.vault[name] = password
        self.save_vault()
        print(f"Password for '{name}' created successfully.")

    # Delete password
    def delete_password(self):
        self.list_passwords()
        name_to_delete = input("Enter the name of the password to delete: ")
        if name_to_delete in self.vault:
            confirm = input(f"Are you sure you want to delete '{name_to_delete}'? (y/n): ")
            if confirm.lower() == 'y':
                del self.vault[name_to_delete]
                self.save_vault()
                print(f"Password for '{name_to_delete}' deleted successfully.")
            else:
                print("Deletion aborted.")
        else:
            print(f"No password found with the name '{name_to_delete}'.")
    
    # Main 
    def main(self):
        while True:
            print("\n AES_PASSWORD_ENCRYPTION_PROGRAM")
            print("\nPassword Manager Options:")
            print("1. List passwords")
            print("2. Create password")
            print("3. Delete password")
            print("4. Retrieve password")
            print("5. Exit")
            choice = input("Choose an option: ")

            if choice == '1':
                self.list_passwords()
            elif choice == '2':
                self.create_password()
            elif choice == '3':
                self.delete_password()
            elif choice == '4':
                self.get_password()
            elif choice == '5':
                print("Exiting Password Manager.")
                break
            else:
                print("Invalid option, try again.")

if __name__ == "__main__":
    try:
        vault_name = input("Enter your vault name: ")
        manager = PasswordManager(vault_name)
        manager.run()
    except KeyboardInterrupt:
        print("\n\nProgram was cancelled")
