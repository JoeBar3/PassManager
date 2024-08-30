import secrets
import string
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sys import platform


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


def readpasses(masterPass):
    with open("salt.txt", "rb") as f:
        salt = f.read()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=48000,
    )
    encryptionkey = base64.urlsafe_b64encode(kdf.derive(masterPass))
    f = Fernet(encryptionkey)
    with open("passwords.txt", "rb") as fi:
        encryptedContent = fi.read()
    try:
        content = f.decrypt(encryptedContent)
        return content
    except:
        print("Password incorrect")
        return ""


def clearScreen():
    if platform == "win32":
        os.system("cls")
    else:
        os.system("clear")


try:
    with open("salt.txt", "rb") as file:
        salt = file.read()
except IOError:
    setUp()

passwords = ""
while passwords == "":
    masterPass = input("Please enter your master password: ")
    masterPass = masterPass.encode()
    passwords = readpasses(masterPass)
    passwords = passwords.decode()

while True:
    clearScreen()
    print("MAIN MENU:\n1: Read passwords\n2: Add a password\n3:Change your master password\n4: Exit")
    choice = input("Enter your selection: ")
    match choice:
        case "1":
            if passwords == "Empty":
                print(
                    "There are no passwords currently saved. Please add passwords from the menu.")
                input("Press enter to continue. ")
        case "2":
            pass
        case "3":
            pass
        case "4":
            clearScreen()
            break
