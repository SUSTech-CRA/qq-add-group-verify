from flask import Flask, render_template, request, flash, url_for, session, redirect
from forms import *
import time
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
import base64
from authlib.integrations.flask_client import OAuth
import os
import requests
import json
from datetime import timedelta

app = Flask(__name__)

app.permanent_session_lifetime = timedelta(minutes=30)
app.config.from_pyfile(os.path.join(".", "config/sustech.py"), silent=False)

# oauth settings
issuer = app.config['OAUTH2_ISSUER']
clientId = app.config['OAUTH2_CLIENT_ID']
clientSecret = app.config['OAUTH2_CLIENT_SECRET']
oidcDiscoveryUrl = f'{issuer}/.well-known/openid-configuration'

oauth = OAuth(app=app)
oauth.register(
    name='keycloak',
    client_id=clientId,
    client_secret=clientSecret,
    server_metadata_url=oidcDiscoveryUrl,
    client_kwargs={
        'scope': 'openid email profile',
        'code_challenge_method': 'S256'  # enable PKCE
    },
)


@app.route('/service/qqv/token', methods=['GET', 'POST'])
def homepage():
    user = session.get('user')
    if user is not None:
        form = get_token()

        if request.method == 'POST':
            if form.validate() == False:
                # print("not validate!")
                return render_template('validate_failed.html', form=form, userinfo=user)
            else:
                token = generate_token(form.name.data)
                return render_template('token.html', token=token, userinfo=user)
        elif request.method == 'GET':
            return render_template('token.html', form=form, userinfo=user)
    else:
        # print("not login!!!")
        return redirect('/service/qqv/')


@app.route('/service/qqv/')
def index():
    user = session.get('user')
    userinfo_json = None
    form = None
    if user is not None:
        form = get_token()
        userinfo_json = user
        # print(userinfo_json['name'])
    return render_template('index.html', userinfo=userinfo_json, form=form)


@app.route('/service/qqv/login')
def login():
    redirect_uri = url_for('auth', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)


@app.route('/service/qqv/auth')
def auth():
    # print("ENTER AUTH STATE")
    tokenResponse = oauth.keycloak.authorize_access_token()
    # print(tokenResponse)
    # userinfo = oauth.keycloak.userinfo(request)

    # idToken = oauth.keycloak.parse_id_token(token=tokenResponse)
    idToken = tokenResponse
    session.permanent = True
    if idToken:
        session['user'] = json.loads(json.dumps(idToken))['userinfo']
        session['tokenResponse'] = tokenResponse

    return redirect('/service/qqv/')


@app.route('/service/qqv/api')
def api():
    if not 'tokenResponse' in session:
        return "Unauthorized", 401

    # the following should be much easier...
    # see https://docs.authlib.org/en/latest/client/frameworks.html#auto-update-token
    tokenResponse = session['tokenResponse']
    # get current access token
    # check if access token is still valid
    # if current access token is valid, use token for request
    # if current access token is invalid, use refresh token to obtain new access token
    # if sucessfull, update current access token, current refresh token
    # if current access token is valid, use token for request

    # call userinfo endpoint as an example
    access_token = tokenResponse['access_token']
    userInfoEndpoint = f'{issuer}/protocol/openid-connect/userinfo'
    userInfoResponse = requests.post(userInfoEndpoint,
                                     headers={'Authorization': f'Bearer {access_token}', 'Accept': 'application/json'})

    return userInfoResponse.text, 200


@app.route('/service/qqv/logout')
def logout():
    tokenResponse = session.get('tokenResponse')

    if tokenResponse is not None:
        # propagate logout to Keycloak
        refreshToken = tokenResponse['refresh_token']
        endSessionEndpoint = f'{issuer}/protocol/openid-connect/logout'

        requests.post(endSessionEndpoint, data={
            "client_id": clientId,
            "client_secret": clientSecret,
            "refresh_token": refreshToken,
        })

    session.pop('user', None)
    session.pop('tokenResponse', None)
    return redirect('/service/qqv/')


cmac_secret = app.config['AES_HMAC_SECRET']


def generate_token(qq_num):
    timestamp = time.time()
    hmac_str = str(qq_num) + "|" + str(int(timestamp))
    cobj = CMAC.new(cmac_secret, ciphermod=AES)
    cobj.update(hmac_str.encode())
    hmac = cobj.hexdigest()
    token = str(int(timestamp)) + "|" + hmac
    # print(token)
    base64_token = base64.b64encode(token.encode('ascii'))
    # print(base64_token)
    return base64_token.decode("utf-8")


if __name__ == "__main__":
    # print(app.config)
    app.run(host='127.0.0.1', port='28081')
