# password_manager
Working, early version terminal only, AES-256 encryption for your passwords, hash authenticated master password to get in.
Backup and restore passwords with commands "backup" and "restore", only restores latest backup.
Change your master password with "change"

Known bug:
Once authenticated into the program, the only way to reveal all passwords without reentering your master password is to edit the note of an entry and wanted to reprint everything.

Encrypted data and keys are saved at the same location, so not recommended for serious use yet. The program is clunky and a bit redundent. I tried to encrypt the AES-256 key and iv with hash, but ran into the same issue of the hash key still being stored on the disk. Oh well ¯\_(ツ)_/¯


Dependency: Cryptograpy module
pip install cryptography
