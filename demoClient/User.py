from json import dumps

import requests
from constants import *
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from util import *


class User:
    def __init__(self, usn: str = None, uid: int = None, pubKey: RSA.RsaKey = None):
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

    def postRequest(self, path: str, data: dict):
        """
        Creates a post request with a signature
        """
        signer = PKCS115_SigScheme(self.getKeys())
        data["uid"] = self.getUid()
        data["apiSig"] = signer.sign(dumps(data))
        return requests.post(f"{PROTOCOL}://{HOSTNAME}:{PORT}/{path}", json=data)

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
