from . import db, bcrypt
import datetime
from flask_login import UserMixin


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    authy_id = db.Column(db.String(60))
    email = db.Column(db.String(120), unique=True)
    username = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(120))
    otp_enabled = db.Column(db.Boolean, default=False)
    date_created = db.Column(db.DateTime)

    def __init__(self, authy_id, email, username, password, otp_enabled):
        self.authy_id = authy_id
        self.email = email
        self.username = username
        self.password = bcrypt.generate_password_hash(password)
        self.date_created = datetime.datetime.utcnow()
        self.otp_enabled = otp_enabled

    def __repr__(self):
        return 'User {}'.format(self.username)

