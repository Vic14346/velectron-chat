from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps
from datetime import datetime, timedelta
import os
import secrets
from cryptography.fernet import Fernet
import json

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///velectron.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Encryption key for messages
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)

# ==================== DATABASE MODELS ====================

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    avatar = db.Column(db.String(1), default='V')
    status = db.Column(db.String(20), default='online')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    
    messages = db.relationship('Message', backref='author', lazy=True, cascade='all, delete-orphan')
    servers = db.relationship('Server', secondary='user_servers', backref='members')
    
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'avatar': self.avatar,
            'status': self.status,
            'created_at': self.created_at.isoformat()
        }


class Server(db.Model):
    __tablename__ = 'servers'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    icon = db.Column(db.String(1), default='V')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_private = db.Column(db.Boolean, default=True)
    
    owner = db.relationship('User', backref='owned_servers')
    channels = db.relationship('Channel', backref='server', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'owner_id': self.owner_id,
            'icon': self.icon,
            'is_private': self.is_private,
            'created_at': self.created_at.isoformat()
        }


class Channel(db.Model):
    __tablename__ = 'channels'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    channel_type = db.Column(db.String(20), default='text')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    messages = db.relationship('Message', backref='channel', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'server_id': self.server_id,
            'channel_type': self.channel_type,
            'created_at': self.created_at.isoformat()
        }


class Message(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    edited_at = db.Column(db.DateTime)
    is_encrypted = db.Column(db.Boolean, default=True)
    
    reactions = db.relationship('Reaction', backref='message', lazy=True, cascade='all, delete-orphan')
    
    def encrypt_content(self, content):
        return cipher_suite.encrypt(content.encode()).decode()
    
    def decrypt_content(self, encrypted_content):
        return cipher_suite.decrypt(encrypted_content.encode()).decode()
    
    def to_dict(self, decrypt=False):
        content = self.content
        if decrypt and self.is_encrypted:
            try:
                content = self.decrypt_content(self.content)
            except:
                content = "[Decryption failed]"
        
        return {
            'id': self.id,
            'content': content,
            'author': self.author.to_dict(),
            'channel_id': self.channel_id,
            'created_at': self.created_at.isoformat(),
            'edited_at': self.edited_at.isoformat() if self.edited_at else None,
            'reactions': [r.to_dict() for r in self.reactions]
        }


class Reaction(db.Model):
    __tablename__ = 'reactions'
    
    id = db.Column(db.Integer, primary_key=True)
    emoji = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='reactions')
    
    def to_dict(self):
        return {
            'id': self.id,
            'emoji': self.emoji,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat()
        }


user_servers = db.Table('user_servers',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('server_id', db.Integer, db.ForeignKey('servers.id'), primary_key=True)
)

# ==================== ROUTES ====================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        if not data.get('username') or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Missing required fields'}), 400
        
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 409
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists'}), 409
        
        user = User(
            username=data['username'],
            email=data['email'],
            avatar=data['username'][0].upper()
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        default_server = Server(
            name=f"{data['username']}'s Server",
            description="Your personal server",
            owner_id=user.id,
            icon=user.avatar
        )
        db.session.add(default_server)
        db.session.commit()
        
        for channel_name in ['general', 'announcements', 'random']:
            channel = Channel(
                name=channel_name,
                description=f"{channel_name} channel",
                server_id=default_server.id
            )
            db.session.add(channel)
        
        db.session.commit()
        
        access_token = create_access_token(identity=user.id)
        
        return jsonify({
            'message': 'User registered successfully',
            'access_token': access_token,
            'user': user.to_dict()
        }), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Missing email or password'}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not user.check_password(data['password']):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        user.last_seen = datetime.utcnow()
        db.session.commit()
        
        access_token = create_access_token(identity=user.id)
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user': user.to_dict()
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(user.to_dict()), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/servers', methods=['GET'])
@jwt_required()
def get_servers():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        servers = user.owned_servers + user.servers
        
        return jsonify([server.to_dict() for server in servers]), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/servers', methods=['POST'])
@jwt_required()
def create_server():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data.get('name'):
            return jsonify({'error': 'Server name is required'}), 400
        
        server = Server(
            name=data['name'],
            description=data.get('description', ''),
            owner_id=user_id,
            icon=data.get('icon', 'V'),
            is_private=data.get('is_private', True)
        )
        
        db.session.add(server)
        db.session.commit()
        
        for channel_name in ['general', 'announcements']:
            channel = Channel(
                name=channel_name,
                description=f"{channel_name} channel",
                server_id=server.id
            )
            db.session.add(channel)
        
        db.session.commit()
        
        return jsonify(server.to_dict()), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/servers/<int:server_id>/channels', methods=['GET'])
@jwt_required()
def get_channels(server_id):
    try:
        channels = Channel.query.filter_by(server_id=server_id).all()
        return jsonify([channel.to_dict() for channel in channels]), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/channels/<int:channel_id>/messages', methods=['GET'])
@jwt_required()
def get_messages(channel_id):
    try:
        messages = Message.query.filter_by(channel_id=channel_id).order_by(Message.created_at).all()
        return jsonify([msg.to_dict(decrypt=True) for msg in messages]), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/channels/<int:channel_id>/messages', methods=['POST'])
@jwt_required()
def send_message(channel_id):
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data.get('content'):
            return jsonify({'error': 'Message content is required'}), 400
        
        channel = Channel.query.get(channel_id)
        if not channel:
            return jsonify({'error': 'Channel not found'}), 404
        
        message = Message(
            content=cipher_suite.encrypt(data['content'].encode()).decode(),
            author_id=user_id,
            channel_id=channel_id,
            is_encrypted=True
        )
        
        db.session.add(message)
        db.session.commit()
        
        return jsonify(message.to_dict(decrypt=True)), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/messages/<int:message_id>', methods=['DELETE'])
@jwt_required()
def delete_message(message_id):
    try:
        user_id = get_jwt_identity()
        message = Message.query.get(message_id)
        
        if not message:
            return jsonify({'error': 'Message not found'}), 404
        
        if message.author_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        db.session.delete(message)
        db.session.commit()
        
        return jsonify({'message': 'Message deleted'}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/messages/<int:message_id>/reactions', methods=['POST'])
@jwt_required()
def add_reaction(message_id):
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data.get('emoji'):
            return jsonify({'error': 'Emoji is required'}), 400
        
        message = Message.query.get(message_id)
        if not message:
            return jsonify({'error': 'Message not found'}), 404
        
        existing = Reaction.query.filter_by(
            message_id=message_id,
            user_id=user_id,
            emoji=data['emoji']
        ).first()
        
        if existing:
            db.session.delete(existing)
        else:
            reaction = Reaction(
                emoji=data['emoji'],
                user_id=user_id,
                message_id=message_id
            )
            db.session.add(reaction)
        
        db.session.commit()
        
        return jsonify(message.to_dict(decrypt=True)), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/users/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    try:
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(user.to_dict()), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/users/<int:user_id>/status', methods=['PUT'])
@jwt_required()
def update_user_status(user_id):
    try:
        current_user_id = get_jwt_identity()
        
        if current_user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if data.get('status') in ['online', 'idle', 'dnd', 'offline']:
            user.status = data['status']
            user.last_seen = datetime.utcnow()
            db.session.commit()
        
        return jsonify(user.to_dict()), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500


@app.before_request
def before_request():
    db.create_all()


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
