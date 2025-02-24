import eventlet
eventlet.monkey_patch()

from flask import request, jsonify
from flask import Flask, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, send
from flask_socketio import SocketIO, emit
from collections import defaultdict
from flask_cors import CORS

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
#from flask_oauthlib.client import OAuth
from authlib.integrations.flask_client import OAuth

import os

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'Ukraine TimeBeCreative Magic'
socketio = SocketIO(app, cors_allowed_origins="*")



app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "postgresql://timebecreativechats_user:FSXgz1BxC3gboldt8qhHCIDAyaOJgqrp@dpg-custgannoe9s7393uhf0-a.frankfurt-postgres.render.com/timebecreativechats")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

CORS(app, origins=["*"], allow_headers=["Content-Type", "Authorization", "Acces-Control-Allow-Origin"])

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    avatar_url = db.Column(db.String(255))
    
    chats = db.relationship('Chat', secondary='user_chats', back_populates="users")
    def __repr__(self):
        return f'<User {self.name}>'
    
class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=True)
    
    users = db.relationship('User', secondary='user_chats', back_populates = "chats")
    def __repr__(self):
        return f'<CHat {self.name}>'
    
class UserChats(db.Model):
    __tablename__ = 'user_chats'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), primary_key=True)
    
    
class ChatRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default="pending")
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])



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

online_users = {}

#Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#class User(UserMixin):
 #   def __init__(self, user_id, name, email, avatar_url):
 #       self.id = user_id
  #      self.name = name
  #      self.email = email
  #      self.avatar_url = avatar_url
        
@socketio.on('connect')
def handle_connect():
  print(f"New connection: {request.sid}")
  user_id = request.args.get('user_id')
  email = request.args.get('email')
  avatar = request.args.get('avatar')
  
  print(f"Received user_id: {user_id}, email: {email}, avatar: {avatar}")
  
  if user_id and email:
      online_users[user_id] = {"email": email, "avatar": avatar, "session_id": request.sid}
      print(f"Online users: {online_users}")
      emit('update_online_users', list(online_users.values()), broadcast=True)
      
@socketio.on('disconnect')
def handle_disconnect():
    user_id = None
    for uid, data in list(online_users.items()):
        if data["session_id"] == request.sid:
            user_id = uid
            del online_users[uid]
            break
        
    if user_id:
        emit('update_online_users', list(online_users.values()), broadcast=True)
            
            
        
        
        
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
   # return users.get(user_id)

#users = {}

chat_requests = {}



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
    
    user_id = user_info.get('sub')
    user_avatar = user_info['picture']
    
    user_name = user_info.get('name', 'Unknow')
    user_email = user_info.get('email', 'Unknow')
    
    user = User.query.filter_by(user_id=user_id).first()
    
    if not user:
        user = User(user_id=user_id, name=user_name, email=user_email, avatar_url=user_avatar)
        db.session.add(user)
        db.session.commit()
     
    login_user(user)
    
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
    
    recipient = User.query.filter_by(email=recipient_email).first()
    if not recipient:
        return jsonify({"message": "User not found"}), 404
    
    existing_request = ChatRequest.query.filter_by(
        sender_id=current_user.id, recipient_id=recipient.id, status="pending"
    ).first()
    if existing_request:
         return jsonify({"message": "Request already sent"}), 400 
     
    new_request = ChatRequest(sender_id=current_user.id, recipient_id=recipient.id)
    db.session.add(new_request)
    db.session.commit()
    
    return jsonify({"message": f"Request sent to {recipient_email}"}), 200
    


@app.route('/get_chat_requests', methods=['GET'])
@login_required
def get_chat_requests():
  
    requests = ChatRequest.query.filter_by(recipient_id=current_user.id, status="pending").all()
    request_list = [{"id": r.id, "sender_email": r.sender.email, "sender_name": r.sender.name} for r in requests]
    return jsonify({"requests": request_list})






@app.route('/accept_chat_request', methods=['POST'])
@login_required
def accept_chat_request():
    data = request.json
    request_id = data.get("request_id")
    
    chat_request = ChatRequest.query.get(request_id)
    if not chat_request or chat_request.recipient_id != current_user.id:
        return jsonify({"message": "Invalid request"}), 400
    
    chat = Chat()
    chat.users.append(chat_request.sender)
    chat.users.append(chat_request.recipient)
    
    db.session.add(chat)
    chat_request.status = "accepted"
    db.session.commit()
    
    return jsonify({"message": "Chat request accepted"}), 200
    

@app.route('/reject_chat_request', methods=['POST'])
@login_required
def reject_chat_request():
  data = request.json
  request_id = data.get("request_id")
    
  chat_request = ChatRequest.query.get(request_id)
  if not chat_request or chat_request.recipient_id != current_user.id:
        return jsonify({"message": "Invalid request"}), 400
    
  chat_request.status = "rejected"
  db.session.commit()
    
  return jsonify({"message": "Request rejected"}), 200

@app.route('/get_chats')
@login_required
def get_chats():
    chats = current_user.chats
    chat_list = []
    
    for chat in chats:
        other_users = [user for user in chat.users if user.id != current_user.id]
        
        if len(other_users) == 1:
            chat_name = other_users[0].name
        else:
            chat_name = chat.name
            
        chat_list.append({"chat_id": chat.id, "chat_name": chat_name})
    
    
  
    return jsonify({'chats': chat_list})
  

def get_chats_for_user(user_email):
    user = User.query.filter_by(email=user_email).first()
    if not user:
        return []
    
    chats = user.chats
    chat_list = []
    
    for chat in chats:
        other_users = [u.name for u in chat.users if u.email != user_email]
        chat_list.append({
            'chat_id': chat.id,
            'chat_name': other_users[0] if len(other_users) == 1 else chat.name,
            'participants': [u.name for u in chat.users]
        })
    return chat_list
  
@app.route('/chat/<int:chat_id>')
@login_required
def chat(chat_id):
    chat = Chat.query.get(chat_id)
    if not chat or current_user not in chat.users:
        return redirect(url_for('index'))
    
    other_users = [user for user in chat.users if user.id != current_user.id]
    recipient_name = other_users[0].name if len(other_users) == 1 else "Group chat"
    return render_template('chat.html', chat_id=chat_id, recipient_name=recipient_name)

    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    port = int(os.environ.get("PORT", 10000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)