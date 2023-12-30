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
from encode_decode_token import encrypt_token

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
oauth.register(
    name='sustech',
    client_id='MbnoOoIzqJlrWvY4MzT5NycPPEesAVc2dAdr',
    client_secret='TPJDwOURCpfdkBi0BBgPLvm4tyuAkawpVB7N',
    access_token_url='https://cas.sustech.edu.cn/cas/oauth2.0/accessToken',
    authorize_url='https://cas.sustech.edu.cn/cas/oauth2.0/authorize',
    api_base_url='https://cas.sustech.edu.cn/cas/oauth2.0/profile',
    client_kwargs={
        'token_endpoint_auth_method': 'client_secret_basic',
        "token_placement": "header"
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
                token = encrypt_token(time.time(), form.name.data, app.config['AES_HMAC_SECRET'])
                return render_template('token.html', token=token, userinfo=user)
        elif request.method == 'GET':
            return render_template('token.html', form=form, userinfo=user)
    else:
        # print("not login!!!")
        return redirect('/service/qqv/')


@app.route('/service/qqv/')
def index():
    # get qq from query_param
    if request.args.get("qq") is not None and request.args.get("qq").isdigit():
        session['query_qq'] = str(request.args.get("qq"))

    user = session.get('user')
    userinfo_json = None
    form = None
    if user is not None:
        form = get_token()
        userinfo_json = user
        # print(userinfo_json['name'])
    if request.args.get("qq") is not None:
        return render_template('index.html', userinfo=userinfo_json, form=form, query_qq=str(session.get('query_qq')))
    else:
        return render_template('index.html', userinfo=userinfo_json, form=form)


@app.route('/service/qqv/login')
def login():
    redirect_uri = url_for('auth', _external=True)
    return oauth.sustech.authorize_redirect(redirect_uri)


@app.route('/service/qqv/auth')
def auth():
    # print("ENTER AUTH STATE")
    tokenResponse = oauth.sustech.authorize_access_token()
    access_token = json.loads(str(tokenResponse).replace("'", '"'))['access_token']
    # print(access_token)
    userInfoEndpoint = 'https://cas.sustech.edu.cn/cas/oauth2.0/profile'
    userInfoResponse = requests.get(userInfoEndpoint, params={"access_token": access_token})
    # print(userInfoResponse.text)
    # userinfo = oauth.keycloak.userinfo(request)

    # idToken = oauth.keycloak.parse_id_token(token=tokenResponse)
    idToken = tokenResponse
    session.permanent = True
    if idToken:
        session['user'] = json.loads(userInfoResponse.text)['attributes']
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

    # if tokenResponse is not None:
    #     # propagate logout to Keycloak
    #     refreshToken = tokenResponse['refresh_token']
    #     endSessionEndpoint = f'{issuer}/protocol/openid-connect/logout'
    #
    #     requests.post(endSessionEndpoint, data={
    #         "client_id": clientId,
    #         "client_secret": clientSecret,
    #         "refresh_token": refreshToken,
    #     })

    session.pop('user', None)
    session.pop('tokenResponse', None)
    # return redirect('/service/qqv/')
    return redirect('https://cas.sustech.edu.cn/cas/logout')


if __name__ == "__main__":
    # print(app.config)
    app.run(host='127.0.0.1', port='28081')
