from authy.api import AuthyApiClient
from . import app
from functools import wraps
from flask_login import current_user
from flask import redirect, url_for


def get_auth():
    auth_user = AuthyApiClient(app.config['API_KEY'])
    return auth_user


def protect_route(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        else:
            return f(*args, **kwargs)

    return wrap



