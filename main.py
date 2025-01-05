'''
setup.py should be run first
future plans: 
    find way to export for android and/or web app
        sync files between phone and computer?

not recommended for serious use yet
'''
import csv
import os
import encryption
from datetime import datetime
import user
import setup
import backup

directory = setup.directory
key_file = setup.key_file
iv_file = setup.iv_file
encrypted_file = setup.encrypted_file
decrypted_file = setup.decrypted_file
hash_file = setup.output_hash
backup_dir = backup.backup_dir
#now = backup.now


#Function to read the TSV file
def read_tsv(file_path):
    userList = []
    with open(file_path, newline='') as file:
        reader = csv.reader(file, delimiter='\t')
        for row in reader:
            userList.append(user.User(row[0], row[1], row[2], row[3], row[4]))
        
    print("TSV file processed")
    return userList

# Function to write a list of dictionaries to the TSV file
def write_tsv(file_path, data):
    with open(file_path, "w", newline='') as file:
        writer = csv.writer(file, delimiter='\t')
        #user needs to be in list format
        writer.writerows([user.listFormat() for user in data])
    print("TSV file updated")

#decrypts encrypted password list, returns userList
def load_UserList():
    #salt, hash_value = encryption.hash_read_file(hash_file)
    key = encryption.decrypt(encryption.read_file(key_file), hash_file)
    iv = encryption.decrypt(encryption.read_file(iv_file), hash_file)

    encryption.aes_256_decrypt_file(key, iv, encrypted_file, decrypted_file)
    #loads in 'temp.tsv'
    userList = read_tsv(decrypted_file)
    #deletes 'temp.tsv'
    setup.secure_delete(decrypted_file)
    return userList

def save_session():
    key = encryption.decrypt(encryption.read_file(key_file), hash_file)
    iv = encryption.decrypt(encryption.read_file(iv_file), hash_file)

    #overwrites 'temp.tsv' to update
    write_tsv(decrypted_file, userList)
    #AES-256 encrypts 'temp.tsv'
    encryption.aes_256_encrypt_file(key, iv, decrypted_file, encrypted_file)
    #deletes 'temp.tsv'
    setup.secure_delete(decrypted_file)

userList = []
cont = auth = False

#sets up if TSV file does not exist
if not os.path.exists(encrypted_file):
    setup.setup()
    userList = load_UserList()
    cont = auth = True
else: #authenticates if TSV file exists
    if encryption.hash_auth(hash_file):
        userList = load_UserList()
        cont = auth = True

#program only runs if master password authenticated
while cont:
    ask = input("find/add/remove/edit/list: (1/2/3/4/5)\n")
    #secret quit option
    if ask == "0" or ask == "":
        cont = False
        break
    #finds user no password
    if ask == "1":
        user.findUser(userList)
    #adds user  
    if ask == "2":
        user.addUser(userList)
        #save_session()
    #removes user
    if ask == "3":
        user.delUser(userList)
        #save_session()
    #edits user
    if ask == "4":
        user.editUser(userList)
        #save_session()
    #prints all users no passwords
    if ask == "5":
        user.printList(userList)
    #change master password
    if ask == "change" and encryption.hash_auth(hash_file):
        print("Changing master password...")
        #decrypts key and iv
        key = encryption.decrypt(encryption.read_file(key_file), hash_file)
        iv = encryption.decrypt(encryption.read_file(iv_file), hash_file)
        print("Key and IV decrypted.")
	    #decrypts tsv
        encryption.aes_256_decrypt_file(key, iv, encrypted_file, decrypted_file)
	    #sets new password
        salt, hash_value = encryption.hash_password(encryption.genPass())
        encryption.hash_write_file(hash_file, salt, hash_value)
        #sets new key and iv
        encryption.create_key(key_file)
        encryption.create_iv(iv_file)
        key = encryption.read_file(key_file)
        iv = encryption.read_file(iv_file)
        #encrypts tsv
        encryption.aes_256_encrypt_file(key, iv, decrypted_file, encrypted_file)
        setup.secure_delete(decrypted_file)
        #encrypts key and iv
        encrypted_key = encryption.encrypt(key, hash_file)
        encrypted_iv = encryption.encrypt(iv, hash_file)
        encryption.write_file(encrypted_key, key_file)
        encryption.write_file(encrypted_iv, iv_file)
        print("Key and IV encrypted.")
        print("Master password successfully changed.")
    #creates password backup
    if ask == "backup":
        save_session()
        backup.backup_files(directory, f"{backup_dir}/{datetime.now().strftime("%Y%m%d_%H%M%S")}")
        userList = load_UserList()
    #restores latest backup
    if ask == "restore" and encryption.hash_auth(hash_file):
        most_recent = backup.find_most_recent_file(backup_dir)
        if most_recent:
            backup.restore_files(f"{backup_dir}/{most_recent}", directory)
            userList = load_UserList()

#makes sure user authenticated
if auth: save_session()