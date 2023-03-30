from json import loads

import requests
from constants import *
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from User import LocalUser, User
from util import *


class Bubble:

    """
    Class denoting chatrooms
    """

    def __init__(self, bid: int = None):
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

    def connect(self):
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
        from Message import Message
        def signTester(msg: Message):
            """
            Tests if the signature is valid
            """
            try:
                signer = PKCS115_SigScheme(
                    User(uid=msg["authUID"]).getPubKey())
                newHash = SHA256.new(msg["content"].encode("utf-8"))
                signer.verify(newHash, stringToBytes(msg["sig"]))
                return True
            except:
                return False
        data = {
            "uid": localUser.getUid(),
            "bid": self.getBid(),
        }
        msgs = loads(requests.post(
            f"http://{HOSTNAME}:{PORT}/api/bubble/messageRequest", json=data).text)
        # decrypt message
        keys = localUser.getKeys()
        cipher = PKCS1_OAEP.new(keys)
        signed = []
        for msg in msgs:
            """
            Decrypt message
            """
            msg.update({"content": cipher.decrypt(
                stringToBytes(msg["content"])).decode("utf-8")})
            """
            Screen out invalid signatures
            """
            if signTester(msg):
                signed.append(msg)
        return signed
