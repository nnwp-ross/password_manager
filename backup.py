import os
import shutil
import setup
from datetime import datetime

backup_dir = "backup"
now = datetime.now().strftime("%Y%m%d_%H%M%S")

def find_most_recent_file(directory):
    most_recent_file = None
    most_recent_time = None
    try:
        os.listdir(directory)
    except FileNotFoundError:
        os.makedirs(directory)
    for filename in os.listdir(directory):
        #print(filename)
        if (most_recent_file is None or filename > most_recent_file):
            most_recent_file = filename

    return most_recent_file

def clear_directory(dir):
    for filename in os.listdir(dir):
        file_path = os.path.join(dir, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)  # Remove the file
            #elif os.path.isdir(file_path):
                #shutil.rmtree(file_path)  # Remove the directory
        except Exception as e:
            print(f'Failed to delete {file_path}. Reason: {e}')

def backup(source_dir, copy_dir, source_files):
    print("Backing up...")
    os.makedirs(copy_dir, exist_ok=True)
    for file in source_files:
        shutil.copy(file, copy_dir)
    print(f"Data from '{source_dir}' backed up to '{copy_dir}'")

def restore(copy_dir, source_dir, source_files):
    print("Restoring...")
    try:
        copy_dir, source_dir = source_dir, copy_dir
        clear_directory(copy_dir)
        for file in source_files:
            shutil.copy(file, copy_dir)
        copy_dir, source_dir = source_dir, copy_dir
        print(f"Backup from '{copy_dir}' restored to '{source_dir}'")
    except FileNotFoundError:
        print("File not found")

def backup_files(directory, backup_dir):
    if os.path.exists(f"{backup_dir}/.DS_Store"):
        setup.secure_delete("backup/.DS_Store")
    key_file = f"{directory}/key.bin"
    iv_file = f"{directory}/iv.bin"
    encrypted_file = f"{directory}/encrypted.bin"
    hash_file = f'{directory}/hash'
    source_files = [encrypted_file, hash_file, key_file, iv_file]
    backup(directory, backup_dir, source_files)

def restore_files(backup_dir, directory):
    if os.path.exists(f"{backup_dir}/.DS_Store"):
        setup.secure_delete("backup/.DS_Store")
    key_file = f"{backup_dir}/key.bin"
    iv_file = f"{backup_dir}/iv.bin"
    encrypted_file = f"{backup_dir}/encrypted.bin"
    hash_file = f'{backup_dir}/hash'
    source_files = [encrypted_file, hash_file, key_file, iv_file]
    restore(backup_dir, directory, source_files)

#only runs if backup.py is run directly
if __name__ == '__main__':
    if os.path.exists(setup.directory):
        directory = setup.directory
        #now = "20240712_205744"
        #error handling
        if os.path.exists(f"{backup_dir}/.DS_Store"):
            setup.secure_delete("backup/.DS_Store")

        while True:
            now = datetime.now().strftime("%Y%m%d_%H%M%S")
            ask = input("what action? ")

            if ask == "backup":
                backup_files(directory, f"{backup_dir}/{now}")

            elif ask == "restore":
                #print(most_recent)
                most_recent = find_most_recent_file(backup_dir)
                if most_recent:
                    restore_files(f"{backup_dir}/{most_recent}", directory)
            
            else: break
    else: print("Please run setup.py first")