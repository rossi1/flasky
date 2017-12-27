from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_bootstrap import Bootstrap

app = Flask(__name__)
app.config.from_object(Config)
db  = SQLAlchemy(app)
bootstrap = Bootstrap(app)
bcrypt = Bcrypt(app)
lm = LoginManager(app)
lm.login_view = 'login'
lm.session_protection = 'strong'

from . import views