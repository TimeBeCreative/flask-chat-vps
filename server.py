import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, redirect, url_for, session
from flask_socketio import SocketIO, send

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
#from flask_oauthlib.client import OAuth
from authlib.integrations.flask_client import OAuth

import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Ukraine TimeBeCreative Magic'
socketio = SocketIO(app, cors_allowed_origins="*")

#Google OAuth

oauth = OAuth(app)
google = oauth.register(
    'google',
    client_id="517190451083-g0pu07rgo5nuvdo2oh16ebcqquc3qcjp.apps.googleusercontent.com",
    client_secret="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",
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    refresh_token_url='https://accounts.google.com/o/oauth2/token',
    client_kwargs={
        'scope': 'openid email profile',
        #'redirect_uri':'https://flask-chat-vps.onrender.com/login/callback'
    },
    userinfo_endpoint ='https://openidconnect.googleapis.com/v1/userinfo',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
  #  scope='email profile',
   # redirect_uri='https://flask-chat-vps.onrender.com/login/callback'
    #request_token_params={'scope': 'email profile'},
  #  authorize_url='https://www.googleapis.com/oauth2/v1/',
  #  request_token_url=None,
  #  access_token_method='POST',
   # authorize_url='https://accounts.google.com/o/oauth2/auth',
  #  access_token_url='https://accounts.google.com/o/oauth2/token',
  #  scope='email profile'
)

#Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_id, name, email):
        self.id = user_id
        self.name = name
        self.email = email
        
@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

users = {}



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return google.authorize_redirect(
        url_for('authorized', _external=True, _scheme='https')
        )

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('google_token', None)
    return redirect(url_for('index'))

@app.route('/login/callback')
def authorized():
    token = google.authorize_access_token()
    

    user_info = google.get('https://openidconnect.googleapis.com/v1/userinfo').json()
    
    user_id = user_info['id']
    user_name = user_info['name']
    user_email = user_info['email']
    
    if user_id not in users:
        users[user_id] = User(user_id, user_name, user_email)
        
    login_user(users[user_id])
    
    return redirect(url_for('index'))
def get_google_oauth_token():
    return session.get('google_token')

@socketio.on('message')
@login_required
def handle_message(msg):
    print(f'{current_user.name}: {msg}')
    send(f'{current_user.name}: {msg}', broadcast=True)
    


    
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)