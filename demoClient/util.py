from base64 import b64decode, b64encode

from constants import *
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def genKey(pwd: str):
    """
    Generates a new key pair
    """
    keys = RSA.generate(BIT_LENGTH)
    with open("keys.pem", "wb") as f:
        f.write(keys.export_key("PEM", passphrase=pwd))
        f.close()
    print("New RSA Key Pair Generated")


def readKey(pwd: str):
    """
    Reads the key file and outputs the key pairing
    """
    with open("keys.pem", "rb") as f:
        return RSA.import_key(f.read(), passphrase=pwd)


def keyTest(pwd: str):
    """
    Verifies if the key functions properly.
    """
    keys = readKey(pwd)
    cipher = PKCS1_OAEP.new(keys)
    from os import urandom
    testMessage = urandom(64)
    del urandom
    encrypted = cipher.encrypt(testMessage)
    decrypted = cipher.decrypt(encrypted)
    if testMessage == decrypted:
        print("RSA Key is functional")
    else:
        raise Exception("KeyNotValidError")


def bytesToString(byteData: bytes):
    """
    Converts bytes into b64 encoded string
    """
    return b64encode(byteData).decode("utf-8")


def stringToBytes(stringData: str):
    """
    Converts b64 encoded string into bytes
    """
    return b64decode(stringData.encode("utf-8"))
