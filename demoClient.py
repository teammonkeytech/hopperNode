from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import requests

BIT_LENGTH = 2048   # 1024, 2048, 3072 are available
HOSTNAME = "localhost"
PORT = "5000"

def genKey(pwd):
    """
    Generates a new key pair
    """
    keys = RSA.generate(BIT_LENGTH)
    with open("keys.pem", "wb") as f:
        f.write(keys.export_key("PEM", passphrase=pwd))
        f.close()
    print("New RSA Key Pair Generated")

def readKey(pwd):
    """
    Reads the key file and outputs the key pairing
    """
    with open("keys.pem", "rb") as f:
        return RSA.import_key(f.read(), passphrase=pwd)

def keyTest(pwd):
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

def dataEncode(data):
    from json import dumps
    from base64 import urlsafe_b64encode
    return urlsafe_b64encode(dumps(data).encode("utf-8")).decode("utf-8")

def dataDecode(raw):
    from json import loads
    from base64 import urlsafe_b64decode
    return dict(loads(urlsafe_b64decode(raw.encode("utf-8")).decode("utf-8")))

class User: 
    def __init__(self, usn):
        self.usn = usn
        self.uid = int(requests.get(f"http://{HOSTNAME}:{PORT}/api/user/id?data={dataEncode({'usn': usn})}").text)
        self.pubKey = requests.get(f"http://{HOSTNAME}:{PORT}/api/user/pubKey?data={dataEncode({'usn': usn})}").text


class localUser(User):
    def __init__(self, usn, pwd, keys):
        self.pwd = pwd
        self.keys = keys
        User.__init__(self, usn)

    def auth(self):
        self.pubKey = self.keys.public_key().export_key().decode("utf-8")
        data = {
            "usn": self.usn,
            "pwd": self.pwd,
            "pubKey": self.pubKey,
        }
        encodedData = dataEncode(data)
        pg = requests.get(f"http://{HOSTNAME}:{PORT}/api/user/auth?data={encodedData}")
        print(pg.text)

if __name__ == "__main__":
    # usn = input("Username: ")
    # pwd = input("Password: ")
    usn = "test"
    pwd = "test" # testing pwd replace when in production
    try: 
        keyTest(pwd)
    except:
        input("Generate new keys? Reauthentication with server required")
        genKey(pwd)
    keys = readKey(pwd)
    clientUser = localUser(usn, pwd, keys=keys)
    clientUser.auth()
    print(clientUser.uid)
    # bubbleRequest([0, 1])

    