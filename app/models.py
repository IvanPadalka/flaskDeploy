from datetime import datetime as dt
from flask_login import UserMixin
from flask_bcrypt import generate_password_hash
from flask_bcrypt import check_password_hash
from app import db, login


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    image_file = db.Column(db.String(20), nullable=False, default='default.jpeg')
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=dt.utcnow)
    admin = db.Column(db.Boolean, default=False)

    def is_admin(self):
        return self.admin

    def __repr__(self):
        return f'User[{self.username}, {self.email}]'
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=dt.utcnow)
    updatetime = db.Column(db.DateTime, default=dt.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return f'Post[{self.body}]'
