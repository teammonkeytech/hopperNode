from Bubble import Bubble
from Message import Message
from User import LocalUser
from util import *

if __name__ == "__main__":
    genKey("test")
    user1 = LocalUser("test", "test", readKey("test"))
    user2 = LocalUser("demo", "demo", readKey("test"))
    sessionBubble = Bubble()
    sessionBubble.new(user2)
    sessionBubble.invite(user1)
    newMessage = Message(
        author=user2, bubble=sessionBubble, content="Hello World")
    newMessage.commit()
    print(sessionBubble.msgRequest(user2))
