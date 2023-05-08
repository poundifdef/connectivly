# Connectivly

**Add OAuth to your API in a few lines of code.**

Connectivly is an OAuth provider which requires minimal configuration. 
It allows your users to create apps for your platform,
enables "sign in with YOUR APP", and handles the entire OAuth dance.

You can add OAuth + OIDC to your existing application by adding a single 
authenticated endpoint to approve OAuth requests. 

Connectivly doesn't "own" your users database - it assumes you're already 
managing users and accounts in your own application. It work alonside your DB,
Auth0, Sign In With Google, or other third party identity provider.

## Getting Started

Connectivly is packaged as a single go binary. You just need to configure 1 option:
a callback URL to your app.

### 1. Run Connectivly Server

``` bash
$ export CONNECTIVLY_REDIRECT_URL="https://your-app.example.com/connectivly"
$ go run connectivly

Listening... http://localhost:3000

API Key: zWp2kjQSmN85saBgeWkWF6Riz1GmQEhR

Client 1 App
Client ID: client1
Client Secret: secret1

Client 2 App
Client ID: client2
Client Secret: secret2
```

The app will listen on `http://localhost:3000`. It will automatically generate
an API key and example client apps for testing.


### 2. Add a `/connectivly` endpoint to your app.
This endpoint **must** be authenticated (ie, users must be logged in to be able to reach this.)

During the auth flow, the user will be redirected to the URL you specify in 
`CONNECTIVLY_REDIRECT_URL`, which is `https://your-app.example.com/connectively?token=12345`
in this example.

Your app should make a an API call to connectivly as follows:

``` bash
curl -XPOST -H 'X-API-KEY: zWp2kj...' \
    -H "Content-type: application/json" \
    -d '{"user": "test@example.com"}' \
    'http://localhost:3000/api/auth_session/12345/approve'
```

This call is saying "We authorize `test@example.com` to log in." It will return a `redirect_uri`.
Redirect the user there and connectivly completes the OAuth dance.

Before you do this, you can call `GET /api/auth_session/12345`. This returns information about
the app, end-user, and scopes requested. If you don't want to approve the session, make a POST
request to `/deny` instead.

#### Flask Example

Here is an example using Flask:

``` py
@app.route("/connectivly")
@login_required
def connectivly_auth():
    session_id = request.args["token"]
    approval = requests.post(
            "http://localhost:3000/api/auth_session/" + session_id + "/approve",
            json={"user": "test@example.com"},
            headers={"X-API-KEY": "zWp2kj..."},
    ).json()
    return redirect(approval['redirect_uri'])
```

### 3. Authorize using OAuth

Using one of the Client ID credentials, you can now implement an oauth flow against your application.
Use "openid" as the scope.