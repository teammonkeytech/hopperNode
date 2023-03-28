import requests
from Bubble import Bubble
from constants import *
from Crypto.Cipher import PKCS1_OAEP
from User import User
from util import *


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
