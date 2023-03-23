import flask
import bcrypt
import sqlalchemy as sa

app = flask.Flask(__name__)
engine = sa.create_engine("sqlite:///server.db") # for small servers

def init():
    # creates table if it doesn't exist
    metadata = sa.MetaData()
    users = sa.Table("Users", metadata,
                    sa.Column("username", sa.String(255), nullable=False),
                    sa.Column("passwordHash", sa.String(255), nullable=False),
                    sa.Column("publicKey", sa.String(255), nullable=False)
                    )
    metadata.create_all(engine, checkfirst=True)

@app.route("/api/authenticate")
def auth():
    """
    auth data should include:
    - username
    - password
    - new public key
    """
    raw = flask.request.args.get("data")
    import base64, json
    data = dict(json.loads(base64.urlsafe_b64decode(raw.encode("utf-8")).decode("utf-8")))
    """
    TODO
    Should use the arguments in data (username, password, publicKey)
    username and password should be used to authenticate updating of public key
    password should be hashed before being saved to the database (use bcrypt)
    public key should be served to clients who request it (by username) so they can
    create encrypted messages readable only by the holder of the private key
    """
    return "Success"


if __name__ == "__main__":
    init()
    app.run()