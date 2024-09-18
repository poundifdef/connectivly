from flask import Flask, request, redirect, url_for, session
from authlib.integrations.flask_client import OAuth

import requests
import jwt

app = Flask(__name__)
app.secret_key = "foobar"

oauth = OAuth(app)

BASE_URL = 'http://localhost:3000'

oauth.register(
    name="foo",
    api_base_url="http://localhost:5000",
    server_metadata_url=BASE_URL+"/auth/oauth2/.well-known/openid-configuration",
    client_id="client1",
    client_secret="secret1",
    client_kwargs={"scope": "openid"},
    fetch_token=lambda: session.get('token'),
)


@app.route("/")
def homepage():
    redirect_uri = url_for("auth", _external=True)
    return oauth.foo.authorize_redirect(redirect_uri)

@app.route("/view")
def view():
    resp = oauth.foo.get("users/me")
    return resp.text

@app.route("/auth")
def auth():
    token = oauth.foo.authorize_access_token()
    session['token'] = token
    return redirect('/view')

class Connectivly(object):

    def __init__(self, api_key, base_url=None):
        self.api_key = api_key
        self.jwks = None
        self.base_url = 'http://localhost:3000'

        if base_url is not None:
            self.base_url = base_url

    def _jwks(self):
        if self.jwks is None:
            rc = requests.get(self.base_url + '/auth/jwks.json')
            if rc.status_code == 200:
                self.jwks = rc.json()

        return self.jwks

    def get_login_session(self, session_id):
        session = requests.get(
            self.base_url + "/api/auth_session/" + session_id,
            headers={'X-API-KEY': self.api_key}
        )

        return session.json()

    def approve_login_session(self, session_id):
        approval = requests.post(
            self.base_url + "/api/auth_session/" + session_id + "/approve",
            json={"user": "test@example.com"},
            headers={'X-API-KEY': self.api_key}
        ).json()

        return approval
    def validate_token(self, token, remote=False):
        # Get JWKS data
        jwks = self._jwks()

        decoded = None

        # Try decoding the key against each public key
        for public_key in jwks['keys']:
            try:
                key = jwt.algorithms.RSAAlgorithm.from_jwk(public_key)
                decoded = jwt.decode(token, key=key, algorithms=['RS256'])
            except Exception as ex:
                print(ex)
                continue

        # If we have a valid JWT and want to verify it against Connectivly
        if decoded is not None and remote:

            # Validate the JWT against the server
            rc = requests.post(self.base_url + "/api/introspect", data={"token": token}, headers={'X-API-KEY': self.api_key})
            if rc.status_code != 200:
                decoded = None
            else:
                if rc.json()['active'] != True:
                    decoded = None

        # JWT contains the application, user id, and scopes
        return decoded

connectivly = Connectivly('local-api-key')

@app.route("/users/me")
def me():
    auth = request.headers['Authorization'].split(' ')[1]
    token = str(connectivly.validate_token(auth, True))
    return "Token: " + token

@app.route("/provider/connectivly")
def connectivly_auth():
    token = request.args["token"]
    session = connectivly.get_login_session(token)

    # Logic to validate session
    print(session)

    approval = connectivly.approve_login_session(token)
    return redirect(approval['redirect_uri'])


if __name__ == "__main__":
    app.run(debug=True)