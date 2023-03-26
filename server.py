import flask
import bcrypt
import asyncio
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
import json

app = flask.Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///server.db"
db = SQLAlchemy()


class Users(db.Model):
    uid = db.Column("uid", db.Integer, primary_key=True,
                    unique=True, nullable=False)
    usn = db.Column("usn", db.String(255), unique=True, nullable=False)
    pwdHash = db.Column("pwdHash", db.LargeBinary, nullable=False)
    pubKey = db.Column("pubKey", db.String(255), nullable=False)


class Bubbles(db.Model):
    entid = db.Column("id", db.Integer, primary_key=True, nullable=False)
    bid = db.Column("bid", db.Integer, nullable=False)
    uid = db.Column("uid", db.Integer, nullable=False)


class Messages(db.Model):
    mid = db.Column("mid", db.Integer, primary_key=True, nullable=False)
    authUID = db.Column("authUID", db.Integer, nullable=False)
    recipientUID = db.Column("recipeintUID", db.Integer, nullable=False)
    bid = db.Column("bid", db.Integer, nullable=False)
    time = db.Column("time", db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    content = db.Column("content", db.String(), nullable=False)
    sig = db.Column("sig", db.String(), nullable=False)


def decode(raw):
    from base64 import urlsafe_b64decode
    return dict(json.loads(urlsafe_b64decode(raw.encode("utf-8")).decode("utf-8")))


@app.route("/api/user/auth", methods=["POST"])
async def authUser():
    data = flask.request.get_json()
    query = db.select(Users).where(Users.usn == data["usn"])
    storedUser = db.session.execute(query).fetchone()
    if storedUser != None:
        if bcrypt.checkpw(data["pwd"].encode("utf-8"), storedUser[0].pwdHash):
            # update public key if new one is available
            if storedUser[0].pubKey != data["pubKey"]:
                storedUser[0].pubKey = data["pubKey"]
                db.session.commit()
                return "Key updated"
            return "Authorized"
        return "Invalid"
    # add new user if key isn't in database
    user = Users(
        usn=data["usn"],
        pwdHash=bcrypt.hashpw(data["pwd"].encode("utf-8"), bcrypt.gensalt()),
        pubKey=data["pubKey"],
    )
    db.session.add(user)
    db.session.commit()
    return "Registered"


@app.route("/api/user/id", methods=["POST"])
async def uid():
    data = flask.request.get_json()
    query = db.select(Users).where(Users.usn == data["usn"])
    storedUser = db.session.execute(query).fetchone()
    if storedUser != None:
        return str(storedUser[0].uid)
    return f"User {data['usn']} not found"


@app.route("/api/user/usn", methods=["POST"])
async def usn():
    data = flask.request.get_json()
    query = db.select(Users).where(Users.uid == data["uid"])
    storedUser = db.session.execute(query).fetchone()
    if storedUser != None:
        return storedUser[0].usn
    return f"User {data['uid']} not found"

@app.route("/api/user/pubKey", methods=["POST"])
async def upubkey():
    data = flask.request.get_json()
    query = db.select(Users).where(Users.uid == data["uid"])
    storedUser = db.session.execute(query).fetchone()
    if storedUser != None:
        return storedUser[0].pubKey
    return f"User {data['uid']} not found"


@app.route("/api/bubble/new", methods=["POST"])
async def newRoom():
    data = flask.request.get_json()
    # get largest bubble id so far
    query = db.select(Bubbles).order_by(Bubbles.bid.desc())
    bubbles = db.session.execute(query).fetchone()
    if bubbles == None:
        data["bid"] = 0
    else:
        data["bid"] = bubbles[0].bid + 1
    room = Bubbles(
        bid=data["bid"],
        uid=data["uid"]
    )
    db.session.add(room)
    db.session.commit()
    db.session.refresh(room)
    # return the bid
    return str(room.bid)

async def checkRoomExist(bid):
    # returns True if room exists in db, False if not
    query = db.select(Bubbles).where(Bubbles.bid == bid)
    bubbles = db.session.execute(query).fetchone()
    return bubbles is not None

async def checkUserInRoom(bid, uid):
    # returns True if user is in the room, returns False is not
    query = db.select(Bubbles).where(Bubbles.bid == bid, Bubbles.uid == uid)
    bubbles = db.session.execute(query).fetchone()
    return bubbles is not None

@app.route("/api/bubble/invite", methods=["POST"])
async def inviteToRoom():
    data = flask.request.get_json()
    # write a verification that the person making the request is actually in the room
    if not await checkRoomExist(data["bid"]):
        return f"Bubble {data['bid']} not found"
    if await checkUserInRoom(data["bid"], data["uid"]):
        return f"User {data['uid']} already in bubble"
    room = Bubbles(
        bid=data["bid"],
        uid=data["uid"]
    )
    db.session.add(room)
    db.session.commit()
    return "Success"


@app.route("/api/bubble/uids", methods=["POST"])
async def bubbleUids():
    data = flask.request.get_json()
    query = db.select(Bubbles).where(Bubbles.bid == int(data["bid"]))
    storedBubble = db.session.execute(query).fetchall()
    if storedBubble != None:
        return [bubble[0].uid for bubble in storedBubble]
    return f"Bubble {data['bid']} not found"


@app.route("/api/msg/commit", methods=["POST"])
async def msgCommit():
    data = flask.request.get_json()
    print(data)
    newMsg = Messages(
        authUID=data["authUID"],
        recipientUID=data["recipientUID"],
        bid=data["bid"],
        content=data["content"],
        sig=data["sig"]
    )
    # TODO add measures to verify signature before commiting
    db.session.add(newMsg)
    db.session.commit()
    return "Created"

if __name__ == "__main__":
    db.init_app(app)
    with app.app_context():
        db.create_all()
    app.run()  # comment out in production
