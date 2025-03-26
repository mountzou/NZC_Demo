import os
import requests
import uuid

from flask import Flask, render_template, session, redirect, url_for, request

from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

oauth = OAuth(app)
keyrock = oauth.register(
    name='keyrock',
    client_id=os.getenv('OAUTH2_CLIENT_ID'),
    client_secret=os.getenv('OAUTH2_CLIENT_SECRET'),
    access_token_url=os.getenv('OAUTH2_ACCESS_TOKEN_URL'),
    authorize_url=os.getenv('OAUTH2_AUTHORIZE_URL'),
    client_kwargs={'scope': 'openid profile email'},
)

from functools import wraps


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
@login_required
def index():
    return render_template('index.html', message="Hello, World!")


@app.route('/test')
def test():
    return render_template('test.html')


@app.route('/login')
def login():
    session['nonce'] = str(uuid.uuid4())
    session['state'] = str(uuid.uuid4())
    redirect_uri = url_for('authorize', _external=True)

    return keyrock.authorize_redirect(
        redirect_uri,
        state=session['state'],
        nonce=session['nonce']
    )


@app.route('/authorize')
def authorize():
    if 'state' not in session:
        return "State is missing in session!", 400

    if request.args.get('state') != session['state']:
        return "State does not match!", 400

    token = keyrock.authorize_access_token()

    if not token.get('access_token'):
        return "Access token is missing!", 400

    headers = {'Authorization': f"Bearer {token['access_token']}"}
    response = requests.get(os.getenv('OAUTH2_USERINFO_URL'), headers=headers)

    if response.status_code == 200:
        user_info = response.json()
        session['email'] = user_info['email']
    else:
        return f"Failed to fetch user info: {response.status_code} - {response.text}"

    return redirect(url_for('index'))


@app.route('/logout/')
def logout():
    session.clear()
    request_url = f"{os.getenv('OAUTH2_LOGOUT_URL')}?_method=DELETE&client_id={os.getenv('OAUTH2_CLIENT_ID')}"
    return redirect(request_url)


if __name__ == '__main__':
    app.run(debug=True)
