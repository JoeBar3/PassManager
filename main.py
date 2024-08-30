import secrets
import string
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def passwordGen():
    chars = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ""
        for i in range(12):
            password += secrets.choice(chars)
        if any(c.isupper() for c in password) and any(ispunctuation(c) for c in password) and any(c.isdigit() for c in password):
            break
    return password


def ispunctuation(char):
    for punc in string.punctuation:
        if char == punc:
            return True
    return False


def setUp():
    masterPass = input("Enter your master password: ")
    masterPass = masterPass.encode()
    salt = os.urandom(16)
    with open("salt.txt", "wb") as f:
        f.write(salt)
    print(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=48000,
    )
    encryptionkey = base64.urlsafe_b64encode(kdf.derive(masterPass))
    f = Fernet(encryptionkey)
    encryptedContent = f.encrypt(b"Empty")
    with open("passwords.txt", "wb") as f:
        f.write(encryptedContent)


setUp()
with open("salt.txt", "rb") as f:
    salt = f.read()
    print(salt)
