import csv
import encryption
import os
import getpass

directory = 'data'
key_file = f"{directory}/key.bin"
iv_file = f"{directory}/iv.bin"
encrypted_file = f"{directory}/encrypted.bin"
decrypted_file = f"{directory}/temp.tsv"
output_hash = f'{directory}/hash'
ask = True

#example user entries
data = [
    ["Google", "google.com", "yourname@gmail.com", "password", ""],
    ["Roblox", "roblox.com", "yourname@email.net", "abc123", "roblox is fun"],
    ["Netflix", "netflix.com", "yourdads@email-address.com", "password-sharing", "2FA enabled, contact him for code"],
]

def setup():
    #creates directory where data is stored
    os.makedirs(directory, exist_ok=True)
    #creates tsv file to be encrypted
    with open(decrypted_file, "w", newline='') as file:
        writer = csv.writer(file, delimiter='\t')
        writer.writerows(data)

    print("TSV file created successfully.")

    #sets password
    #password = input("Set the master password: ")
    password = getpass.getpass("Set the master password: ")
    salt, hash_value = encryption.hash_password(password)
    encryption.hash_write_file(output_hash, salt, hash_value)
    #creates key and iv
    encryption.create_key(key_file)
    encryption.create_iv(iv_file)
    #reads key and iv
    key = encryption.read_file(key_file)
    iv = encryption.read_file(iv_file)
    #encrypts tsv
    encryption.aes_256_encrypt_file(key, iv, decrypted_file, encrypted_file)
    #encrypts key and iv
    encrypted_key = encryption.encrypt(encryption.file_to_bytes(key_file), output_hash)
    encrypted_iv = encryption.encrypt(encryption.file_to_bytes(iv_file), output_hash)
    encryption.write_file(encrypted_key, key_file)
    encryption.write_file(encrypted_iv, iv_file)
    
    #deletes decrypted file
    secure_delete(decrypted_file) 

#file deletion made by ai
def secure_delete(file, passes=3):
    if os.name == 'nt': #detects if running on Windows
        with open(file, 'ba+', buffering=0) as delfile:
            length = delfile.tell()
        with open(file, 'br+', buffering=0) as delfile:
            for _ in range(passes):
                delfile.seek(0)
                delfile.write(os.urandom(length))
        os.remove(file)
    else: #unix only command
        os.system(f'shred -u {file}')

#only runs if setup.py is run directly
if __name__ == '__main__':
    #checks if setup.py was already ran, helps prevent data loss
    if os.path.exists(encrypted_file):
        while True:
            ask = input("setup.py was already ran, running it again will overwrite your data. \nContinue? 1/0\n")
            try:
                ask = bool(int(ask))
                break
            except ValueError:
                print("Invalid input.")
        
    if ask:
        setup()
        print("main.py is now ready to be used.")
    else:
        print("setup.py aborted.")
