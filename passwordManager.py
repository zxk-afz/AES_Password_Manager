import os
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json
from colorama import Fore, init
from getpass import getpass
import string
import random

# Initialize colorama
init(autoreset=True)

class PasswordManager:
    def __init__(self, vault_path, key_path):
        self.vault_path = vault_path
        self.key_path = key_path
        self.key = self.load_key()
        self.load_vault()
    
    # Load or generate AES encryption key
    def load_key(self):
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as file:
                return file.read()
        else:
            key = get_random_bytes(32)
            with open(self.key_path, "wb") as file:
                file.write(key)
            return key
    
    # Load encrypted vault data
    def load_vault(self):
        if os.path.exists(self.vault_path):
            with open(self.vault_path, "rb") as file:
                encrypted_content = file.read()
            # Create cipher + iv
            cipher = AES.new(self.key, AES.MODE_CBC, iv=encrypted_content[:16])
            # Decrypt and remove padding
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
        encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
        with open(self.vault_path, "wb") as file:
            file.write(cipher.iv + encrypted_data)
    
    # List passwords with most recent entry first
    def list_passwords(self):
        if not self.vault:
            print("No passwords found.")
            return
        sorted_passwords = sorted(self.vault.keys(), key=lambda x: -len(x))
        print("Stored Passwords:")
        for i, name in enumerate(sorted_passwords, 1):
            print(f"{i}. {name}")

    # Get password
    def get_password(self):
        self.list_passwords()
        try:
            index = int(input("Enter the number of the password to view: "))
            sorted_passwords = sorted(self.vault.keys(), key=lambda x: -len(x))
            selected_name = sorted_passwords[index - 1]
            print(f"{Fore.BLUE}Password for '{selected_name}': {self.vault[selected_name]}{Fore.RESET}")
        except (ValueError, IndexError):
            print(f"{Fore.RED}Invalid selection, try again.{Fore.RESET}")

    # Create password entry
    def create_password(self):
        print("Password creator options:")
        print("1. Choose own password")
        print("2. Generate password")
        create_or_generate = input("Choose an option (1/2): ")
        if create_or_generate == "1":
            name = input("Enter password name: ")
            # Verify if name exists
            while name in self.vault:
                print(f"Name {Fore.RED}already in use{Fore.RESET}, enter another one.")
                name = input("Enter password name: ")
            
            password = getpass("Enter password: ")
            confirm_password = getpass("Retype password: ")
            while password != confirm_password:
                print(f"Passwords {Fore.RED}do not match{Fore.RESET}, try again.")
                password = getpass("Enter password: ")
                confirm_password = getpass("Retype password: ")
        elif create_or_generate == "2":
            name = input("Enter password name: ")
            # Generate password
            all_characters = string.ascii_letters + string.digits + string.punctuation
            length = int(input("Enter the length of the password: "))
            password = ''.join(random.choices(all_characters, k=length))
            print("Generated password:", password)
        else: 
            print(f"{Fore.RED}Invalid selection, try again.{Fore.RESET}")

        
        # Save in vault
        self.vault[name] = password
        self.save_vault()
        print(f"Password for '{name}' {Fore.GREEN}created{Fore.RESET} successfully.")

    # Delete password
    def delete_password(self):
        self.list_passwords()
        name_to_delete = input("Enter the name of the password to delete: ")
        if name_to_delete in self.vault:
            confirm = input(f"Are you sure you want to {Fore.RED}delete{Fore.RESET} '{name_to_delete}'? (y/n): ")
            if confirm.lower() == 'y':
                del self.vault[name_to_delete]
                self.save_vault()
                print(f"Password for '{name_to_delete}' {Fore.RED}deleted{Fore.RESET} successfully.")
            else:
                print("Deletion aborted.")
        else:
            print(f"No password found with the name '{name_to_delete}'.")
    
    # Main loop
    def main(self):
        while True:
            print("\nPassword Manager Options:")
            print(f"1. {Fore.MAGENTA}List passwords{Fore.RESET}")
            print(f"2. {Fore.GREEN}Create password{Fore.RESET}")
            print(f"3. {Fore.YELLOW}Delete password{Fore.RESET}")
            print(f"4. {Fore.BLUE}View password{Fore.RESET}")
            print(f"5. {Fore.RED}Exit{Fore.RESET}")
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

# Initialize the vault by getting paths
def initialize_vault():
    print(f"{Fore.BLUE}AES{Fore.RESET} Password Manager")
    existing_vault = input("Do you already have a vault? (yes/no): ").strip().lower()
    if existing_vault == 'yes':
        vault_path = input("Enter your existing vault file path: ").strip()
        key_path = input("Enter your key file path: ").strip()
        if not os.path.exists(vault_path):
            print(f"No vault found at {Fore.RED}'{vault_path}'{Fore.RESET}.")
            return initialize_vault()
        if not os.path.exists(key_path):
            print(f"No key file found at {Fore.RED}'{key_path}'{Fore.RESET}.")
            return initialize_vault()
        print(f"Vault at '{vault_path}' {Fore.GREEN}loaded{Fore.RESET}.")
    else:
        # Prompt the user for info
        vault_name = input("Enter your vault name: ").strip()
        vault_name = vault_name.replace(" ", "-")
        vault_path = f"{vault_name}.vault" 
        key_path = f"key-{vault_name}.bin" 
        
        if os.path.exists(vault_path):
            print(f"A vault already exists at '{vault_path}'. Try another name or path.")
            return initialize_vault()
        
        print(f"Vault '{vault_path}' created.")
    
    return vault_path, key_path

if __name__ == "__main__":
    try:
        vault_path, key_path = initialize_vault()
        manager = PasswordManager(vault_path, key_path)
        manager.main()
    except KeyboardInterrupt:
        print("\n\nProgram was cancelled.")
