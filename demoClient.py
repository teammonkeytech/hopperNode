from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import requests
from json import dumps, loads
from base64 import urlsafe_b64encode, urlsafe_b64decode

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
    return urlsafe_b64encode(dumps(data).encode("utf-8")).decode("utf-8")

def dataDecode(raw):
    return dict(loads(urlsafe_b64decode(raw.encode("utf-8")).decode("utf-8")))

class User: 
    def __init__(self, usn = None, uid = None):
        if uid is not None:
            self.usn = requests.get(f"http://{HOSTNAME}:{PORT}/api/user/usn?data={dataEncode({'uid': uid})}").text
            self.uid = uid
            self.pubKey = requests.get(f"http://{HOSTNAME}:{PORT}/api/user/pubKey?data={dataEncode({'usn': usn})}").text            
        elif usn is not None:
            self.usn = usn
            self.uid = int(requests.get(f"http://{HOSTNAME}:{PORT}/api/user/id?data={dataEncode({'usn': usn})}").text)
            self.pubKey = requests.get(f"http://{HOSTNAME}:{PORT}/api/user/pubKey?data={dataEncode({'usn': usn})}").text            
        else:
            raise LookupError

class LocalUser(User):
    def __init__(self, usn, pwd, keys):
        self.usn = usn
        self.pwd = pwd
        self.keys = keys
        self.auth()
        User.__init__(self, usn)

    # convert into POST requests before deploy
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

    def sign(self, content):
        hash = SHA256.new(content.encode("utf-8"))
        signer = PKCS115_SigScheme(self.keys)
        return signer.sign(hash)

class Bubble:
    def __init__(self, bid = None):
        self.bid = bid
        self.uids = []
        if self.bid is not None:
            self.connect()
    
    def connect(self):
        self.uids = loads(requests.get(f"http://{HOSTNAME}:{PORT}/api/bubble/uids?data={dataEncode({'bid': self.bid})}").text)

class Message:
    def __init__(self, author, bubble, content):
        self.author = author
        self.bubble = bubble
        self.content = content
        self.signature = author.sign(content)
    
    def commit(self):
        data = {
            "authUID": self.author.uid,
            "bid": self.bubble.bid,
            "content": self.content,
            "sig": self.signature,
        }
        requests.get(f"http://{HOSTNAME}:{PORT}/api/msg/commit?data={dataEncode(data)}")

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
    clientUser = LocalUser(usn, pwd, keys=keys)
    sessionBubble = Bubble()
    newMessage = Message(author=clientUser, bubble=sessionBubble, content="Hello World")
    newMessage.commit()
    # bubbleRequest([0, 1])

    