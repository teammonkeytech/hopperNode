from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode
import requests
from json import loads, dumps

BIT_LENGTH = 2048   # 1024, 2048, 3072 are available
PROTOCOL = "http"
HOSTNAME = "localhost"
PORT = "5000"


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

class User:
    def __init__(self, usn: str=None, uid: int=None, pubKey: RSA.RsaKey=None):
        """
        Method to initialize user
        """
        if usn is None:
            usn = requests.post(
                f"http://{HOSTNAME}:{PORT}/api/user/usn", json={'uid': uid}).text
        if uid is None:
            uid = int(requests.post(
                f"http://{HOSTNAME}:{PORT}/api/user/id", json={'usn': usn}).text)
        if pubKey is None:
            pubKey = RSA.import_key(requests.post(
                f"http://{HOSTNAME}:{PORT}/api/user/pubKey", json={'uid': uid}).text)
        self.usn = usn
        self.uid = uid
        self.pubKey = pubKey

    def getUsn(self):
        """
        Returns Username
        """
        return self.usn

    def getUid(self):
        """
        Returns User ID
        """
        return self.uid

    def getPubKey(self):
        """
        Returns the Public Key
        """
        return self.pubKey


class LocalUser(User):
    """
    Extends User class with manipulation of server data
    """
    def __init__(self, usn: str, pwd: str, keys: RSA.RsaKey):
        """
        Initializes Local User Class
        """
        self.usn = usn
        self.pwd = pwd
        self.keys = keys
        self.auth()
        User.__init__(
            self, usn=usn, pubKey=self.keys.public_key().export_key().decode("utf-8"))

    def getPwd(self):
        """
        Returns the Password
        """
        return self.pwd

    def getKeys(self):
        """
        Returns the Private/Public Key Pairing
        Use getPubKey from Class User for Public Key
        """
        return self.keys

    def auth(self):
        """
        Registers public key with associated username and password combination
        """
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
        return bytesToString(signer.sign(hash))


class Bubble:
    """
    Class denoting chatrooms
    """
    def __init__(self, bid: int=None):
        self.bid = bid
        self.uids = []
        if self.bid is not None:
            self.connect()

    def getBid(self):
        """
        Returns attached Bubble ID
        """
        return self.bid
    
    def getUids(self):
        """
        Returns User IDs attached to Bubble
        """
        # try to connect to bubble if still at default value
        if self.uids == []:
            self.connect()
        return self.uids

    def connect(self, user: LocalUser):
        """
        Connects to Bubble and retrieves list of User IDs connected
        """
        self.uids = loads(requests.post(
            f"http://{HOSTNAME}:{PORT}/api/bubble/uids", json={"bid": self.bid}).text)
        return self.getUids()

    def invite(self, user: User):
        """
        Invites a new user to the Bubble
        """
        # for when you are already connected and want to add more users
        data = {
            "bid": self.getBid(),
            "uid": user.getUid()
        }
        status = requests.post(
            f"http://{HOSTNAME}:{PORT}/api/bubble/invite", json=data).text
        print(status)

    def new(self, user: User):
        """
        Creates a new Bubble
        """
        # for when you want to create a new bubble
        data = {
            "uid": user.getUid(),
        }
        self.bid = requests.post(
            f"http://{HOSTNAME}:{PORT}/api/bubble/new", json=data).text

    def msgRequest(self, localUser: LocalUser):
        """
        Returns a list of messages where the signature is verified
        """
        def signTester(msg: Message):
            """
            Tests if the signature is valid
            """
            try:
                signer = PKCS115_SigScheme(User(uid=msg["authUID"]).getPubKey())
                newHash = SHA256.new(msg["content"].encode("utf-8"))
                signer.verify(newHash, stringToBytes(msg["sig"]))
                return True
            except:
                return False
        data = {
            "uid": localUser.getUid(),
            "bid": self.getBid(),
        }
        msgs = loads(requests.post(f"http://{HOSTNAME}:{PORT}/api/bubble/messageRequest", json=data).text)
        # decrypt message
        keys = localUser.getKeys()
        cipher = PKCS1_OAEP.new(keys)
        signed = []
        for msg in msgs:
            """
            Decrypt message
            """
            msg.update({"content": cipher.decrypt(stringToBytes(msg["content"])).decode("utf-8")})
            """
            Screen out invalid signatures
            """
            if signTester(msg):
                signed.append(msg)
        return signed

class Message:
    """
    Class for Messages
    """
    def __init__(self, author: User, bubble: Bubble, content: str):
        """
        Method to initialize new message
        """
        self.author = author
        self.bubble = bubble
        self.content = content
        self.signature = author.sign(content)

    def commit(self):
        """
        Commits message and uploads it to the server encrypted with a signature
        """
        for uid in self.bubble.getUids():
            recipientUser = User(uid=uid)
            cipher = PKCS1_OAEP.new(recipientUser.getPubKey())
            encryptedContent = cipher.encrypt(self.content.encode("utf-8"))
            data = {
                "authUID": self.author.uid,
                "recipientUID": uid,
                "bid": self.bubble.bid,
                "content": bytesToString(encryptedContent),
                "sig": self.signature,
            }
            pg = requests.post(
                f"http://{HOSTNAME}:{PORT}/api/msg/commit", json=data)


if __name__ == "__main__":
    user1 = LocalUser("test", "test", readKey("test"))
    genKey("test")
    user2 = LocalUser("demo", "demo", readKey("test"))
    sessionBubble = Bubble()
    sessionBubble.new(user2)
    sessionBubble.invite(user1)
    newMessage = Message(
        author=user2, bubble=sessionBubble, content="Hello World")
    newMessage.commit()
    print(sessionBubble.msgRequest(user2))