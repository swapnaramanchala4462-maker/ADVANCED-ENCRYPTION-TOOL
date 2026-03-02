import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os
import base64

#------Generate AES-256 key from password------

def generate_key(password,salt):
    kdf=Scrypt(
        salt=salt,
        length=32, #32 bytes=256 bits
        n=2**14,
        r=8,
        p=1,
    )
    key=kdf.derive(password.encode())
    return key

#------Encrypt file------

def encrypt_file(file_path,password):
    try:
        salt=os.urandom(16)
        key=generate_key(password,salt)
        iv=os.urandom(16)
        with open(file_path,"rb") as f:
            data=f.read()
        padder=padding.PKCS7(128).padder()
        padded_data=padder.update(data)+padder.finalize()
        cipher=Cipher(algorithms.AES(key),modes.CBC(iv))
        encryptor=cipher.encryptor()
        encrypted_data=encryptor.update(padded_data)+encryptor.finalize()
        with open(file_path+".end","wb") as f:
            f.write(salt+iv+encrypted_data)
        print("[+] file encrypted successfully!")
    except Exception as e:
        print("[-]encryption failed:",e)
#------encrypt file------

def decrypt_file(file_path,password):
    try:
        with open(file_path,"rb") as f:
            file_data=f.read()
        salt=file_data[:16]
        iv=file_data[16:32]
        encrypted_data=file_data[32:]
        key=generate_key(password,salt)
        cipher=Cipher(algorithms.AES(key),modes.CBC(iv))
        decryptor=cipher.decryptor()
        decrypted_padded=decryptor.update(encrypted_data)+decryptor.finalize()
        unpadder=padding.PKCS7(128).unpadder()
        decrypted_data=unpadder.update(decrypted_padded)+unpadder.finalize()
        output_file=file_path.replace(".enc","_decrypted")
        with open(output_file,"wb") as f:
            f.write(decrypted_data)
        print("[+] file decrypted successfully!")
    except Exception as e:
        print("[-] Decryption Failed:", e)

#------Main Menu(User-friendly interface)------

def main():
    print("="*60)
    print("Advanced AES-256 Encrypteion Tool")
    print("Internship Task-CODTECH IT Solutions")
    print("="*60)
    while True:
        print("\n 1. Encrypted File")
        print("\n 2. Decrypted File")
        print("\n 3. Exit")
        choice=input("Enter your choice:")
        if choice=="1":
            file_path=input("enter file path to encrypt:")
            password=input("enter password:")
            encrypt_file(file_path,password)
        elif choice=="2":
            file_path=input("enter encrypted file_path:")
            password=input("enter password:")
            decrypt_file(file_path,password)
        elif choice=="3":
            print("Exiting tool...")
            break
        else:
            print("Invalid choice. Try again.")
if __name__=="__main__":
    main()
