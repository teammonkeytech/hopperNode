import flask
import bcrypt
import asyncio
from flask_sqlalchemy import SQLAlchemy
import json

app = flask.Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///server.db"
db = SQLAlchemy()

class Users(db.Model):
    uid = db.Column("uid", db.Integer, primary_key=True, unique=True, nullable=False)
    usn = db.Column("usn", db.String(255), unique=True, nullable=False)
    pwdHash = db.Column("pwdHash", db.LargeBinary, nullable=False)
    pubKey = db.Column("pubKey", db.String(255), nullable=False)

class Bubbles(db.Model):
    bid = db.Column("bid", db.Integer, primary_key=True, unique=True, nullable=False)
    uids = db.Column("uid", db.String(), nullable=True)

class Messages(db.Model):
    mid = db.Column("mid", db.Integer, primary_key=True, nullable=False)
    authUID = db.Column("authUID", db.Integer, nullable=False)
    bid = db.Column("bid", db.Integer, nullable=False)
    time = db.Column("time", db.TIMESTAMP, nullable=False)
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
        usn = data["usn"],
        pwdHash = bcrypt.hashpw(data["pwd"].encode("utf-8"), bcrypt.gensalt()),
        pubKey = data["pubKey"],
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

@app.route("/api/bubble/new")
async def newRoom():
    raw = flask.request.args.get("data")
    data = decode(raw)
    room = Bubbles(
        uids = json.dumps(data["uids"])
    )
    db.session.add(room)
    db.session.commit()
    return "Created"

@app.route("/api/bubble/uids", methods=["POST"])
async def bubble_uids():
    raw = flask.request.args.get("data")
    data = decode(raw)
    query = db.select(Bubbles).where(Bubbles.bid == int(data["bid"]))
    storedBubble = db.session.execute(query).fetchone()
    if storedBubble != None:
        return storedBubble[0].uids
    return f"Bubble {data['bid']} not found"

if __name__ == "__main__":
    db.init_app(app)
    with app.app_context():
        db.create_all()
    app.run() # comment out in production