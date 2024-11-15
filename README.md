# AES Password Manager

```bash
  /$$$$$$  /$$$$$$$$  /$$$$$$                                                     
 /$$__  $$| $$_____/ /$$__  $$                                                    
| $$  \ $$| $$      | $$  \__/                                                    
| $$$$$$$$| $$$$$   |  $$$$$$                                                     
| $$__  $$| $$__/    \____  $$                                                    
| $$  | $$| $$       /$$  \ $$                                                    
| $$  | $$| $$$$$$$$|  $$$$$$/                                                    
|__/  |__/|________/ \______/                                                     
                                                                             
                                                                                  
 /$$$$$$$                                                                      /$$
| $$__  $$                                                                    | $$
| $$  \ $$ /$$$$$$   /$$$$$$$ /$$$$$$$ /$$  /$$  /$$  /$$$$$$   /$$$$$$   /$$$$$$$
| $$$$$$$/|____  $$ /$$_____//$$_____/| $$ | $$ | $$ /$$__  $$ /$$__  $$ /$$__  $$
| $$____/  /$$$$$$$|  $$$$$$|  $$$$$$ | $$ | $$ | $$| $$  \ $$| $$  \__/| $$  | $$
| $$      /$$__  $$ \____  $$\____  $$| $$ | $$ | $$| $$  | $$| $$      | $$  | $$
| $$     |  $$$$$$$ /$$$$$$$//$$$$$$$/|  $$$$$/$$$$/|  $$$$$$/| $$      |  $$$$$$$
|__/      \_______/|_______/|_______/  \_____/\___/  \______/ |__/       \_______/
                                                                   
                                                                                  
 /$$$$$$/$$$$   /$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$         
| $$_  $$_  $$ |____  $$| $$__  $$ |____  $$ /$$__  $$ /$$__  $$ /$$__  $$        
| $$ \ $$ \ $$  /$$$$$$$| $$  \ $$  /$$$$$$$| $$  \ $$| $$$$$$$$| $$  \__/        
| $$ | $$ | $$ /$$__  $$| $$  | $$ /$$__  $$| $$  | $$| $$_____/| $$              
| $$ | $$ | $$|  $$$$$$$| $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$$| $$              
|__/ |__/ |__/ \_______/|__/  |__/ \_______/ \____  $$ \_______/|__/              
                                             /$$  \ $$                            
                                            |  $$$$$$/                            
                                             \______/                             
```

A terminal-based password manager that securely stores and manages passwords in an AES-encrypted vault. The vault is protected using AES-256 encryption.

## Features
- Create a new encrypted vault or load an existing one
- Store passwords (kinda the goal)
- List stored passwords in order of creation (newest at the top)
- Retrieve passwords by selection
- Delete passwords with confirmation

## Requirements

This script requires the following libraries:
- `pycryptodome` (for AES encryption)
- `json` (for managing stored data)

To install `pycryptodome`, run:
```bash
pip install pycryptodome
```

## Usage

### 1. Running the Password Manager
Run the script in the terminal:
```bash
python password_manager.py
```

### 2. Password Manager Options:
```bash
1. List passwords
2. Create password
3. Delete password
4. Retrieve password
5. Exit
```