from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from base64 import urlsafe_b64encode, urlsafe_b64decode
import hashlib
import random
import os
import setup
import getpass

def encrypt(data, hash_file):
    salt, has = hash_read_file(hash_file)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(has.encode())
    iv = os.urandom(16)
    cipher = aes_256_create_cipher(key, iv)
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return urlsafe_b64encode(iv + encrypted_data)

def decrypt(encrypted_data, hash_file):
    missing_padding = len(encrypted_data) % 4
    if missing_padding:
        encrypted_data += '=' * (4 - missing_padding)
    
    encrypted_data = urlsafe_b64decode(encrypted_data)
    salt, has = hash_read_file(hash_file)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(has.encode())
    cipher = aes_256_create_cipher(key, iv)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def create_key(key_file):
    if os.path.exists(key_file):
        setup.secure_delete(key_file)
    key = os.urandom(32)
    with open(key_file, "wb") as file:
        file.write(key)
    print("Random 32-bit Key Generated.")
    return key

def create_iv(iv_file):
    if os.path.exists(iv_file):
        setup.secure_delete(iv_file)
    iv = os.urandom(16)
    with open(iv_file, "wb") as file:
        file.write(iv)
    print("Random IV file created.")
    return iv

def write_file(data, output_file):
    print(f"Writing '{output_file}'...")
    with open(output_file, "wb") as file:
        file.write(data)

def read_file(input_file):
    print(f"Reading '{input_file}'...")
    with open(input_file, "rb") as file:
        return file.read()

#AES-128 encrypts input with key to write output (Unused)
def aes_128_encrypt_file(key, input_file, output_file):
    fernet = Fernet(key)

    with open(input_file, "rb") as file:
        file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)

    with open(output_file, "wb") as file:
        file.write(encrypted_data)

    print(f"File '{input_file}' encrypted and saved as '{output_file}'.")

#AES-128 decrypts input with key to write output (Unused)
def aes_128_decrypt_file(key, input_file, output_file):
    fernet = Fernet(key)

    with open(input_file, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = fernet.decrypt(encrypted_data)

    with open(output_file, "wb") as file:
        file.write(decrypted_data)

    print(f"File '{input_file}' decrypted and saved as '{output_file}'.")

#Hash encrypts password, returns salt and hash
def hash_password(password):
    # Generate a random salt
    salt = os.urandom(16)
    # Combine the salt and the password
    salted_password = salt + password.encode('utf-8')
    # Hash the combined string
    hash_value = hashlib.sha256(salted_password).hexdigest()
    return salt, hash_value

#uses salt and hash to verify input
def hash_verify_password(stored_salt, stored_hash, password):
    # Combine the stored salt and the provided password
    salted_password = stored_salt + password.encode('utf-8')
    # Hash the combined string
    hash_value = hashlib.sha256(salted_password).hexdigest()
    # Compare the resulting hash with the stored hash
    return (print("Access authorized.") or True) if hash_value == stored_hash else (print("Password Failed.") or False)

#writes salt and hash to output_file
def hash_write_file(output_file, salt, hash_value):
    with open(output_file, "w") as file:
        file.write(f"{salt.hex()}\n")
        file.write(f"{hash_value}\n")
        print(f"Hash successfully saved to '{output_file}'.")

#process output
def hash_read_file(output_file):
    with open(output_file, "r") as file:
        lines = file.readlines()
        nSalt = bytes.fromhex(lines[0].strip())
        nHash = lines[1].strip()
        print(f"Hash file '{output_file}' read.")
        return nSalt, nHash

#password authentication with output_file
def hash_auth(hash_file):
    auth = getpass.getpass("Master password needed: ")
    salt, hash_value = hash_read_file(hash_file)
    return hash_verify_password(salt, hash_value, auth)

#generates random password with length num
def genWord(num):
    chara = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '<', '.', '>', '/', '?', '{', '[', '}', ']', '~']
    word = ""
    for i in range(num):
        word += chara[random.randint(0, chara.__len__() - 1)]
    return word

#returns random password of num length
def ranWord(num):
    vPass = ""
    while vPass == "":
        rPass = genWord(num)
        ver = input(f"{rPass} : Do you want to use this? (1/0)\n")
        if ver == "1":
            vPass = rPass
            print("Password Set")
    return vPass

#prompts creation of a password
def genPass():
    vPass = getpass.getpass("Input the password (leave blank for random password): ")
    #generates random password of num length           
    if vPass == "":
        while True:
            num = input("How long? (at least 8) ")
            try:
                num = int(num)
                if num >= 8:
                    vPass = ranWord(num)
                    return vPass
                else:
                    print("At least 8 is required.")
            except ValueError:
                print("Please input valid integer.")
    else:
        return vPass

def aes_256_create_cipher(key, iv):
    return Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

#AES-256 encrypts input with key to write output
def aes_256_encrypt_file(key, iv, input_file, output_file):
    with open(input_file, "rb") as file:
        file_data = file.read()

    # Create a cipher object
    cipher = aes_256_create_cipher(key, iv)

    # Pad data to be a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Encrypt the padded data
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, "wb") as file:
        file.write(encrypted_data)

    print(f"File '{input_file}' encrypted and saved as '{output_file}'.")

#decrypts input with key to write output
def aes_256_decrypt_file(key, iv, input_file, output_file):
    with open(input_file, "rb") as file:
        encrypted_data = file.read()

    # Decrypt the data
    cipher = aes_256_create_cipher(key, iv)
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    with open(output_file, "wb") as file:
        file.write(decrypted_data)

    print(f"File '{input_file}' decrypted and saved as '{output_file}'.")

def file_to_bytes(input_file):
    with open(input_file, 'rb') as file:
        return file.read()

def bytes_to_file(input_file, data):
    with open(input_file, 'wb') as file:
        file.write(data)