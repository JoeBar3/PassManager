import secrets
import string


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


print(passwordGen())
