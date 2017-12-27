from . import app, lm, db, bcrypt
from sqlalchemy.exc import IntegrityError
from .forms import SignupForm, LoginForm, AuthForm
from .model import User
from flask_login import current_user, login_required, login_user, logout_user
from flask import redirect, url_for, render_template, flash, request, abort
from .utils import get_auth, protect_route
import datetime


@lm.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
@login_required
def index():
    return 'current user is {}, and the authy client id is {}'.format(current_user.username, current_user.authy_id)


@app.route('/signup', methods=['GET', 'POST'])
@protect_route
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        authy_user = get_auth()
        auth_create_user = authy_user.users.create(form.email.data, form.phone_number.data, form.area_code.data)
        if auth_create_user.ok():
            try:
                user = User(authy_id=auth_create_user.id, email=form.email.data, username=form.username.data,
                            password=form.password.data, otp_enabled=True)
                db.session.add(user)
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
            else:
                login_user(user, remember=True, duration=datetime.timedelta(days=12))
                flash('you were logged in successfully')

                return redirect(request.args.get('next')or url_for('index'))

        else:
            flash('An error occurred!')

    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@protect_route
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and bcrypt.check_password_hash(user.password, form.password.data):
            if user.otp_enabled:
                auth = get_auth()
                request_token = auth.users.request_sms(user.authy_id, {'force': True})
                if request_token.ok():
                    login_user(user, remember=True, duration=datetime.timedelta(days=12))
                    flash('An auth code has been sent to you')
                    return redirect(url_for('verify_auth_code'))
                else:
                    login_user(user, remember=True, duration=datetime.timedelta(days=12))
                    flash('code could\'nt be sent')
                    return redirect(url_for('verify_auth_code'))
            else:
                login_user(user, remember=True, duration=datetime.timedelta(days=12))
                flash('Successfully logged in')
                return redirect(url_for('index'))
        else:
            flash('Invalid login credentials')
    return render_template('signin.html', form=form)


@app.route('/verify-token', methods=['GET', 'POST'])
def verify_auth_code():
    if not current_user.is_authenticated:
        abort(401)
    form = AuthForm()
    if form.validate_on_submit():
        auth = get_auth()
        verify_token = auth.tokens.verify(current_user.authy_id, form.auth_code.data, {'force': True})
        if verify_token.ok():
            return redirect(url_for('index'))
        else:
            flash('token is invalid, please request for a new one, or enter the correct code')
    return render_template('verify_token.html', form=form)


@app.route('/request-token')
def request_new_token():
    if not current_user.is_authenticated:
        abort(401)
    auth = get_auth()
    request_token = auth.users.request_sms(current_user.authy_id, {'force': True})
    if request_token.ok():
        flash('A new code has been sent to your phone number')
        return redirect(url_for('verify_auth_code'))
    else:
        flash('An error couldn\'t send new code')


@app.route('/request-token-call')
def get_token_call():
    if not current_user.is_authenticated:
        abort(401)
    auth = get_auth()
    request_token = auth.users.request_call(current_user.authy_id, {'force': True})
    if request_token.ok():
        flash('you will recieve a call with a code')
        return redirect(url_for('verify_auth_code'))
    else:
        flash('An error occurred!, could\nt place a call')


@app.route('/logout')
def logout():
    logout_user()
    flash('you successfully logged out')
    return redirect(url_for('index'))