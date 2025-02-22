import eventlet
eventlet.monkey_patch()

from flask import request, jsonify
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
      
    },
    userinfo_endpoint ='https://openidconnect.googleapis.com/v1/userinfo',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',

)

#Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_id, name, email, avatar_url):
        self.id = user_id
        self.name = name
        self.email = email
        self.avatar_url = avatar_url
        
@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

users = {}

chat_requests = {}

user_chats = {}

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
    print(user_info)
    
    user_avatar = user_info['picture']
    user_id = user_info.get('sub', 'unknow')
    user_name = user_info.get('name', 'Unknow')
    user_email = user_info.get('email', 'Unknow')
    
    if user_id not in users:
        users[user_id] = User(user_id, user_name, user_email, user_avatar)
        
    login_user(users[user_id])
    
    return redirect(url_for('index'))
def get_google_oauth_token():
    return session.get('google_token')

@socketio.on('message')
#@login_required
def handle_message(msg):
    if not current_user.is_authenticated:
        return
    
    print(f'{current_user.name}: {msg}')
    
    message_data = {
        'username': current_user.name,
        'avatar_url': current_user.avatar_url,
        'message': msg
    }
    send(message_data, broadcast=True)
 
    



@app.route('/send_chat_request', methods=['POST'])
@login_required
def send_chat_request():
    data = request.json
    recipient_email = data.get("recipient_email")
    
    recipient = next((user for user in users.values() if user.email == recipient_email), None)
    if recipient:
        if recipient_email not in chat_requests:
            chat_requests[recipient_email] = []
        chat_requests[recipient_email].append(current_user.email)
        
        return jsonify({"message": f"Request sent to {recipient_email}"}), 200
    else:
        return jsonify({"message": "User not found"}), 404


@app.route('/get_chat_requests', methods=['GET'])
@login_required
def get_chat_requests():
    user_email = current_user.email
    requests = chat_requests.get(user_email, [])
    return jsonify({"requests": requests})






@app.route('/accept_chat_request', methods=['POST'])
@login_required
def accept_chat_request():
    data = request.json
    sender_email = data.get("email")
    
    if not sender_email:
        return jsonify({"message": "Email is required"}), 400
    
    if sender_email in chat_requests.get(current_user.email, []):
        if current_user.email not in user_chats:
            user_chats[current_user.email] = []
        if sender_email not in user_chats:
            user_chats[sender_email] = []
            
        user_chats[current_user.email].append(sender_email)
        user_chats[sender_email].append(current_user.email)
        
        chat_requests[current_user.email].remove(sender_email)
        
        return jsonify({"message": "Request accepted!"}), 200
    return jsonify({"message": "Error!"}), 400

@app.route('/reject_chat_request', methods=['POST'])
@login_required
def reject_chat_request():
    data = request.json
    sender_email = data.get("email")
    
    if sender_email in chat_requests.get(current_user.email, []):
        chat_requests[current_user.email].remove(sender_email)
        return jsonify({"message": "Request rejected"}), 200
    return jsonify({"message": "Error!"}), 400




    
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)