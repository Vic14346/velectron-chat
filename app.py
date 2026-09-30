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
    try:
        return render_template('index.html')
    except:
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Velectron - Setup Required</title>
            <style>
                body { font-family: Arial; text-align: center; padding: 50px; background: #36393f; color: #fff; }
                .container { max-width: 600px; margin: 0 auto; }
                h1 { color: #5865f2; }
                code { background: #2f3136; padding: 10px; display: block; margin: 20px 0; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 Velectron Setup</h1>
                <p>The templates folder is missing index.html</p>
                <p><strong>Solution:</strong></p>
                <ol>
                    <li>Create a <code>templates</code> folder in your project root</li>
                    <li>Create <code>index.html</code> file inside the templates folder</li>
                    <li>Copy the HTML code from your GitHub into index.html</li>
                    <li>Restart the Flask app</li>
                </ol>
                <p>Or check your GitHub repository structure</p>
            </div>
        </body>
        </html>
        ''', 200
