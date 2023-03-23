from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import requests

BIT_LENGTH = 2048   # 1024, 2048, 3072 are available
HOSTNAME = "localhost"
PORT = "5000"

def genKey(passwd):
    """
    Generates a new key pair
    """
    keys = RSA.generate(BIT_LENGTH)
    with open("keys.pem", "wb") as f:
        f.write(keys.export_key("PEM", passphrase=passwd))
        f.close()
    print("New RSA Key Pair Generated")

def readKey(passwd):
    """
    Reads the key file and outputs the key pairing
    """
    with open("keys.pem", "rb") as f:
        return RSA.import_key(f.read(), passphrase=passwd)

def keyTest(passwd):
    """
    Verifies if the key functions properly.
    """
    keys = readKey(passwd)
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

def serverAuth(usn, passwd, publicKey):
    data = {
        "username": usn,
        "password": passwd,
        "publicKey": publicKey,
    }
    from json import dumps
    from base64 import b64encode

    encodedData = b64encode(dumps(data).encode("utf-8")).decode("utf-8")
    del dumps, b64encode
    return requests.get(f"http://{HOSTNAME}:{PORT}/api/authenticate?data={encodedData}")

if __name__ == "__main__":
    # usn = input("Username: ")
    # passwd = input("Password: ")
    usn = "test"    # testing username replace when in production
    passwd = "test" # testing password replace when in production
    try: 
        keyTest(passwd)
    except:
        input("Generate new keys? Reauthentication with server required")
        genKey(passwd)
    keys = readKey(passwd)
    publicKey = keys.public_key().export_key().decode("utf-8")
    serverAuth(usn, passwd, publicKey)
    