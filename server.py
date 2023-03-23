import flask
import bcrypt
import sqlalchemy as sa
import json

app = flask.Flask(__name__)
engine = sa.create_engine("sqlite:///server.db") # for small servers

def init():
    # creates tables if it doesn't exist
    metadata = sa.MetaData()
    users = sa.Table("Users", metadata,
                    sa.Column("uid", sa.Integer, primary_key=True, unique=True, nullable=False),
                    sa.Column("username", sa.String(255), nullable=False),
                    sa.Column("passwordHash", sa.String(255), nullable=False),
                    sa.Column("publicKey", sa.String(255), nullable=False)
                    )
    bubbles = sa.Table("Bubbles", metadata,
                    sa.Column("bid", sa.Integer, primary_key=True, unique=True, nullable=False),
                    sa.Column("uid", sa.String(), nullable=True),
                    )
    msgs = sa.Table("Messages", metadata,
                    sa.Column("mid", sa.Integer, primary_key=True, nullable=False),
                    sa.Column("uidFrom", sa.Integer, nullable=False),
                    sa.Column("uidTo", sa.Integer, nullable=False),
                    sa.Column("timeStamp", sa.TIMESTAMP, nullable=False),
                    sa.Column("content", sa.String(), nullable=False),
                    )
    metadata.create_all(engine, checkfirst=True)

def decode(raw):
    from base64 import urlsafe_b64decode
    return dict(json.loads(urlsafe_b64decode(raw.encode("utf-8")).decode("utf-8")))

@app.route("/api/authenticate")
def auth():
    """
    auth data should include:
    - username
    - password
    - new public key
    """
    raw = flask.request.args.get("data")
    data = decode(raw)
    """
    TODO
    Should use the arguments in data (username, password, publicKey)
    username and password should be used to authenticate updating of public key
    password should be hashed before being saved to the database (use bcrypt)
    public key should be served to clients who request it (by username) so they can
    create encrypted messages readable only by the holder of the private key
    """
    return "Success"

@app.route("/api/bubble")
def bubbles():
    """
    Returns the list of "bubbles" (chatrooms) the user is a part of
    """
    raw = flask.request.args.get("data")
    data = decode(raw)
    """
    TODO
    Search for list of bubbles user is a part of and return that
    """
    bubbles = []
    jsonedBubbles = json.dumps(bubbles)
    return jsonedBubbles

@app.route("/api/messageRequest")
def messages():
    """
    Authenticate user and ensure that they are a part of the bubble
    Returns the list of messages in the requested bubble
    """
    raw = flask.request.args.get("data")
    data = decode(raw)
    """
    Authenticate user
    Then return messages in current bubble
    """
    messages = []
    jsonedMessages = json.dumps(messages)
    return jsonedMessages


if __name__ == "__main__":
    init()
    app.run()