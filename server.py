import eventlet
eventlet.monkey_patch()

import json
from flask import request, jsonify
from flask import Flask, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, join_room, send, emit
from collections import defaultdict
from flask_cors import CORS
from flask_socketio import join_room, leave_room

from pywebpush import webpush, WebPushException


from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
#from flask_oauthlib.client import OAuth
from authlib.integrations.flask_client import OAuth

import os



VAPID_PRIVATE_KEY = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1JwM3pZeEI0S213VHFiTmMKSElpSG80VU5oUHRQOVR1RmJ0NW1qUi96dFRXaFJBTkNBQVMrQWI2NTdKK0hjVzF3MG5KeXZPczVJcUpTTGJxMQp1alZtRlVXdXI3VWxxMS9KQ0YwcEoyT2FqTzdpK0hhQUFYci9GTmtTTnBWbVNZWXR6U04za1lSOAotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg"
VAPID_PUBLIC_KEY = "BL4Bvrnsn4dxbXDScnK86zkiolIturW6NWYVRa6vtSWrX8kIXSknY5qM7uL4doABev8U2RI2lWZJhi3NI3eRhHw"

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'Ukraine TimeBeCreative Magic'
socketio = SocketIO(app, cors_allowed_origins="*")


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "postgresql://postgres.trdofkwvgjdpwcovwahe:Vika123Che123Vika@aws-0-eu-central-1.pooler.supabase.com:6543/postgres?sslmode=require")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

CORS(app, origins=["*"], allow_headers=["Content-Type", "Authorization", "Access-Control-Allow-Origin"])

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

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    
   
    sender = db.relationship('User', backref='messages')
    chat = db.relationship('Chat', backref='messages')
    
class PushSubscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    endpoint = db.Column(db.Text, nullable=False)
    p256dh = db.Column(db.String(255), nullable=False)
    auth = db.Column(db.String(255), nullable=False)
    


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
    
@app.route('/about')
def about():
    return render_template('about.html')

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
    
    session['user_id'] = user_id
    session['user_name'] = user_name
    session['email'] = user_email
    session['avatar'] = user_avatar
    
    print("Saving to session", session)
    
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
def handle_message(data):
    if not current_user.is_authenticated:
        return
    
    chat_id = data.get("chat_id")
    chat_type = data['type']
    message = data.get("message")
    sender_id = current_user.id
    
    if chat_type == 'public':
         public_chat = Chat.query.filter_by(name='Public Chat').first()
         if not public_chat:
             public_chat = Chat(name='Public Chat')
             db.session.add(public_chat)
             db.session.commit()
             
         new_message = Message(chat_id=public_chat.id, sender_id=sender_id, content=message)
         db.session.add(new_message)
         db.session.commit()
    
         emit("message", {
            "chat_id": public_chat.id,
            "username": session.get("user_name"),
            "avatar_url": session.get("avatar"),
            "message": message,
        
        }, room = 'public_chat')
 
    
 
   
    



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
    return render_template('chat.html', chat_id=chat_id, recipient_name=recipient_name, vapid_public_key=VAPID_PUBLIC_KEY)

online_users = {}

@socketio.on("user_connected")
def user_connected():
    print("SESSION DATA", session)
   
    if "email" in session:
        user_name = session.get('user_name')
        email = session.get('email')
        avatar = session.get('avatar')

        print(f"User connected: {user_name}, {email}, {avatar}")
    
        if email:
            join_room('public_chat')
            online_users[email] = {"name": user_name, "email": email, "avatar": avatar}
            emit('online_users', list(online_users.values()), broadcast=True)
   
        
@socketio.on("disconnect")
def user_disconnected():
    if "email" in session:
        email = session.get('email')
        if email in online_users:
            del online_users[email]
            socketio.start_background_task(sync_online_users)
            
def sync_online_users():
    socketio.emit('online_users', list(online_users.values()), broadcast=True)
    
    
@socketio.on('join_room')
@login_required
def handle_join_room(data):
    chat_id = data["chat_id"]
    recipient_name = data["recipient_name"]
    
    
    if chat_id:
        join_room(chat_id)
        
   
        
        if recipient_name != "Public Chat":
            messages = Message.query.filter_by(chat_id=chat_id)\
                .order_by(Message.timestamp.asc())\
                .all()
            message_list = [{
                "chat_id": message.chat_id,
                "username": message.sender.name,
                "avatar_url": message.sender.avatar_url,
                "message": message.content,
                "timestamp": message.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            } for message in messages]
            
            emit('chat_history', message_list, room=request.sid)
        
        
        
def send_push(subscription_info, data):
    try:
        webpush(
            subscription_info=subscription_info,
            data=data,
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims={
                "sub": "mailto:your-email@example.com"
            }
        )
        print("Push notification sent successfully")
    except WebPushException as ex:
        print(f"Failed to send push notification: {ex}")
                
@socketio.on('private_message')
@login_required
def handle_private_message(data):
    chat_id = data["chat_id"]
    message = data["message"]
    sender_id = current_user.id
    
    chat = Chat.query.get(chat_id)
    if not chat or current_user not in chat.users:
        return 
    
    new_message = Message(chat_id=chat_id, sender_id=sender_id, content=message)
    db.session.add(new_message)
    db.session.commit()
    
    emit("message", {
        "chat_id": chat_id,
        "username": session.get("user_name"),
        "avatar_url": session.get("avatar"),
        "message": message,
        
    }, room=chat_id)
    
    for user in chat.users:
        if user.id != sender_id and user.id in user_subscriptions:
            subs = PushSubscription.query.filter_by(user_id=user.id).all()
            for subscription in subs:
                subscription_info = {
                    "endpoint": subscription.endpoint,
                    "keys": {
                        "p256dh": subscription.p256dh,
                        "auth": subscription.auth
                    }
                }
            
                send_push(subscription_info, json.dumps({
                "title": f"New message from {session.get('user_name')}",
                "body": message,
                "icon": "/static/images/LogoSmall.png",
                "url": url_for('chat', chat_id=chat_id, _external=True)
                }))
            

@app.route('/save-subscription', methods=['POST'])
@login_required
def save_subscription():
    subscription = request.json
    keys = subscription.get("keys", {})
    existing = PushSubscription.query.filter_by(user_id=current_user.id).first()
    if existing:
        existing.endpoint = subscription.get("endpoint")
        existing.p256dh = keys.get("p256dh")
        existing.auth = keys.get("auth")
    else:
        new = PushSubscription(
            user_id=current_user.id,
            endpoint=subscription.get("endpoint"),
            p256dh=keys.get("p256dh"),
            auth=keys.get("auth")
        )
        db.session.add(new)
    db.session.commit()
    return jsonify({"success": True}), 201
    
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    port = int(os.environ.get("PORT", 10000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)