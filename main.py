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
    print("Welcome to the password manager.")
    masterPass = input("Please choose a master password: ")
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


def writepasses(masterPass, content):
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
    encryptedContent = f.encrypt(content)
    with open("passwords.txt", "wb") as fi:
        fi.write(encryptedContent)


def cleanPasses(passwords):
    cleanPass = passwords.split("\n")
    length = int((len(cleanPass)-1)/3)
    organisedPasses = []
    account = ["", "", ""]
    index = 0
    for i in range(0, length):
        for j in range(0, 3):
            account[j] = cleanPass[index]
            index += 1
        organisedPasses.append(account.copy())
    return organisedPasses


try:
    with open("salt.txt", "rb") as file:
        salt = file.read()
except IOError:
    setUp()

try:
    with open("passwords.txt", "rb") as file:
        check = file.read()
except IOError:
    setUp()

passwords = ""
while passwords == "":
    masterPass = input("Please enter your master password: ")
    masterPass = masterPass.encode()
    passwords = readpasses(masterPass)
    if passwords != "":
        passwords = passwords.decode()

organisedPasses = cleanPasses(passwords)

while True:
    clearScreen()
    print("MAIN MENU:\n1: Read passwords\n2: Add a password\n3: Change your master password\n4: Exit")
    choice = input("Enter your selection: ")
    match choice:
        case "1":
            if passwords == "Empty":
                print(
                    "There are no passwords currently saved. Please add passwords from the menu.")
                input("Press enter to continue. ")
            else:
                while True:
                    clearScreen()
                    print(
                        "Please select an option:\n 1: Print all passwords\n 2: Print a specific password")
                    outChoice = input("Enter your selection: ")
                    clearScreen()
                    match outChoice:
                        case "1":
                            for i in range(0, len(organisedPasses)):
                                print("URL: " + organisedPasses[i][0])
                                print("Username: " + organisedPasses[i][1])
                                print("Password: " + organisedPasses[i][2])
                            input("Press enter to continue. ")
                            break
                        case "2":
                            Found = False
                            urlToFind = input(
                                "Please enter the URL of the site: ")
                            for i in range(0, len(organisedPasses)):
                                if organisedPasses[i][0] == urlToFind:
                                    print("URL: " + organisedPasses[i][0])
                                    print("Username: " + organisedPasses[i][1])
                                    print("Password: " + organisedPasses[i][2])
                                    input("Press enter to continue. ")
                                    Found = True
                            if Found == False:
                                input("URL not found. Press enter to continue. ")
                            break

        case "2":
            url = input("Enter the url of the site: ")
            username = input("Enter the username for the site: ")
            while True:
                clearScreen()
                print(
                    "You need to select an option:\n1: Choose your own password\n2: Use a randomly generated password")
                passChoice = input("Enter your selection: ")
                match passChoice:
                    case "1":
                        password = input(f"Enter the password for {url}: ")
                        break
                    case "2":
                        password = passwordGen()
                        break
            if passwords == "Empty":
                passwords = url + "\n" + username + "\n" + password + "\n"
            else:
                passwords += url + "\n" + username + "\n" + password + "\n"
            organisedPasses = cleanPasses(passwords)
        case "3":
            masterPass = input("Enter your new master password: ")
            masterPass = masterPass.encode()
            salt = os.urandom(16)
            with open("salt.txt", "wb") as f:
                f.write(salt)
        case "4":
            clearScreen()
            writepasses(masterPass, passwords.encode())
            break
