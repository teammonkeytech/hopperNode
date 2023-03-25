from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import requests
from json import loads

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


class User:
    def __init__(self, usn=None, uid=None, pubKey=None):
        if usn is None:
            usn = requests.post(
                f"http://{HOSTNAME}:{PORT}/api/user/usn", json={'uid': uid}).text
        if uid is None:
            uid = int(requests.post(
                f"http://{HOSTNAME}:{PORT}/api/user/id", json={'usn': usn}).text)
        if pubKey is None:
            pubKey = requests.post(
                f"http://{HOSTNAME}:{PORT}/api/user/pubKey", json={'uid': uid}).text
        self.usn = usn
        self.uid = uid
        self.pubKey = pubKey

    def getUsn(self):
        return self.usn

    def getUid(self):
        return self.uid

    def getPubKey(self):
        return self.pubKey


class LocalUser(User):
    def __init__(self, usn, pwd, keys):
        self.usn = usn
        self.pwd = pwd
        self.keys = keys
        self.auth()
        User.__init__(
            self, usn=usn, pubKey=self.keys.public_key().export_key().decode("utf-8"))

    def getPwd(self):
        return self.pwd

    def getKeys(self):
        return self.keys

    def auth(self):
        self.pubKey = self.keys.public_key().export_key().decode("utf-8")
        data = {
            "usn": self.getUsn(),
            "pwd": self.getPwd(),
            "pubKey": self.getPubKey(),
        }
        pg = requests.post(
            f"http://{HOSTNAME}:{PORT}/api/user/auth", json=data)
        print(pg.text)

    def sign(self, content):
        hash = SHA256.new(content.encode("utf-8"))
        signer = PKCS115_SigScheme(self.getKeys())
        return signer.sign(hash).hex()


class Bubble:
    def __init__(self, bid=None):
        self.bid = bid
        self.uids = []
        if self.bid is not None:
            self.connect()

    def getBid(self):
        return self.bid
    
    def getUids(self):
        return self.uids

    def connect(self):
        self.uids = loads(requests.post(
            f"http://{HOSTNAME}:{PORT}/api/bubble/uids", json={"bid": self.bid}).text)
        return self.getUids()

    def invite(self, user):
        # for when you are already connected and want to add more users
        data = {
            "bid": self.getBid(),
            "uid": user.getUid()
        }
        status = requests.post(
            f"http://{HOSTNAME}:{PORT}/api/bubble/invite", json=data).text
        print(status)

    def new(self, user):
        # for when you want to create a new bubble
        data = {
            "uid": user.getUid(),
        }
        self.bid = requests.post(
            f"http://{HOSTNAME}:{PORT}/api/bubble/new", json=data).text


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
        pg = requests.post(
            f"http://{HOSTNAME}:{PORT}/api/msg/commit", json=data)
        print(pg)


if __name__ == "__main__":
    # usn = input("Username: ")
    # pwd = input("Password: ")
    usn = "test"
    pwd = "test"  # testing pwd replace when in production
    try:
        keyTest(pwd)
    except:
        input("Generate new keys? Reauthentication with server required")
        genKey(pwd)
    keys = readKey(pwd)
    clientUser = LocalUser(usn, pwd, keys=keys)
    sessionBubble = Bubble(1)
    # sessionBubble.new(clientUser.getUid())
    altUser = User(usn="test")
    sessionBubble.invite(altUser)
    newMessage = Message(
        author=clientUser, bubble=sessionBubble, content="Hello World")
    # newMessage.commit()
    # bubbleRequest([0, 1])
