from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from config import Config
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView



app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login = LoginManager(app)
login.login_view = 'auth.login'
login.login_message_category = 'info'
login.session_protection = 'strong'

app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'

admin = Admin(app, name='Admin Page', template_mode='bootstrap3')
from .models import User, Post
import app.forms as  fr
admin.add_view(fr.UserAdminView(User, db.session))
admin.add_view(fr.PostAdminView(Post, db.session))

from app import  models

from app.blueprints.general.views import general_blueprint
from app.blueprints.auth.views import auth_blueprint
from app.blueprints.post.views import post_blueprint
from app.blueprints.administrator.views import administrator_blueprint
from app.blueprints.accaunt.views import accaunt_blueprint
from app.blueprints.post_api.views import postapi_blueprint

app.register_blueprint(general_blueprint)
app.register_blueprint(auth_blueprint)
app.register_blueprint(post_blueprint)
app.register_blueprint(administrator_blueprint)
app.register_blueprint(accaunt_blueprint)
app.register_blueprint(postapi_blueprint)
